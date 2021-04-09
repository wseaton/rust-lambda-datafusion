use lambda_runtime::{handler_fn, Context, Error};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use simple_logger::SimpleLogger;

use arrow::csv;
use arrow::record_batch::RecordBatch;
use arrow::util::pretty::print_batches;
use datafusion::prelude::*;

use s3::creds::Credentials;

use chrono::{DateTime, Utc};
use http::header::{HeaderName, AUTHORIZATION, HOST};
use http::HeaderMap;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs};
use tempfile::Builder;

use anyhow::anyhow;
use hmac::{Mac, NewMac};
use s3::signing::{canonical_request, signed_header_string, signing_key};
use url::Url;

type HmacSha256 = hmac::Hmac<Sha256>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectRequest {
    get_object_context: ObjectContext,
    user_request: UserRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserRequest {
    url: String,
    headers: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectContext {
    output_route: String,
    output_token: String,
    input_s3_url: String,
}

/// This is a made-up example of what a response structure may look like.
/// There is no restriction on what it can be. The runtime requires responses
/// to be serialized into json. The runtime pays no attention
/// to the contents of the response payload.
#[derive(Serialize)]
struct Response {
    req_id: String,
    msg: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // required to enable CloudWatch error logging by the runtime
    // can be replaced with any other method of initializing `log`
    SimpleLogger::new().with_level(LevelFilter::Info).init().unwrap();

    let func = handler_fn(my_handler);
    lambda_runtime::run(func).await?;
    Ok(())
}

const SHORT_DATE: &str = "%Y%m%d";
const LONG_DATETIME: &str = "%Y%m%dT%H%M%SZ";
const LONG_DATE: &str = "%Y%m%dT%H%M%SZ";

use s3::region::Region;

fn scope_string(datetime: &DateTime<Utc>, region: &Region) -> String {
    format!(
        "{date}/{region}/s3-object-lambda/aws4_request",
        date = datetime.format(SHORT_DATE),
        region = region
    )
}

fn authorization_header(
    access_key: &str,
    datetime: &DateTime<Utc>,
    region: &Region,
    signed_headers: &str,
    signature: &str,
) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope},\
            SignedHeaders={signed_headers},Signature={signature}",
        access_key = access_key,
        scope = scope_string(datetime, region),
        signed_headers = signed_headers,
        signature = signature
    )
}

fn string_to_sign(datetime: &DateTime<Utc>, region: &Region, canonical_req: &str) -> String {
    let mut hasher = Sha256::default();
    hasher.update(canonical_req.as_bytes());
    let string_to = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{hash}",
        timestamp = datetime.format(LONG_DATETIME),
        scope = scope_string(datetime, region),
        hash = hex::encode(hasher.finalize().as_slice())
    );
    string_to
}

pub(crate) async fn my_handler(event: ObjectRequest, ctx: Context) -> Result<Response, Error> {
    // extract some useful info from the request
    let obj_ctx: ObjectContext = event.get_object_context;
    let resp = reqwest::get(obj_ctx.input_s3_url).await?;
    let data = resp.bytes().await?;

    println!("Input S3 file is this length: {:?}", data.len());

    let named_tempfile = Builder::new().prefix("data").suffix(".csv").rand_bytes(5).tempfile()?;
    let name = named_tempfile.path().to_str().unwrap();
    println!("Temp filename: {}", name);

    fs::write(name, data).expect("Unable to write to temp file.");

    // Options here in the future could be passed in via headers, like the query itself.
    let mut df_ctx = ExecutionContext::new();
    df_ctx.register_csv("example", name, CsvReadOptions::new().has_header(true).delimiter(b','))?;

    let req_headers = &event.user_request.headers;

    let mut sql = "SELECT Beds, AVG(Year) FROM example GROUP BY Beds";

    if let Some(value) = req_headers.get("x-sql-query") {
        sql = &value;
    }

    let df = df_ctx.sql(&sql)?;
    let res: Vec<RecordBatch> = df.collect().await.expect("Query failed.");

    print_batches(&res).expect("Pretty printing failed.");

    let mut vec = Vec::new();
    // scoping to prevent move
    {
        let mut writer = csv::Writer::new(&mut vec);
        res.iter().for_each(|x| writer.write(x).unwrap());
    }

    let client = reqwest::Client::new();

    let datetime = Utc::now();
    let region = Region::UsEast1;
    let creds = Credentials::default()?;
    let secret_key = creds.secret_key.unwrap();
    let access_key = creds.access_key.unwrap();

    let url = format!(
        "https://{route}.s3-object-lambda.{region}.amazonaws.com/WriteGetObjectResponse",
        route = obj_ctx.output_route,
        region = region.to_string()
    );

    let mut sha = Sha256::default();
    sha.update(&vec);

    let _sha = hex::encode(sha.finalize().as_slice());
    let _url = Url::parse(&url)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        HOST,
        format!(
            "{route}.s3-object-lambda.{region}.amazonaws.com",
            route = obj_ctx.output_route,
            region = region.to_string()
        )
        .parse()
        .unwrap(),
    );

    // headers.insert(CONTENT_LENGTH, content_len.to_string().parse().unwrap());
    // headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
    // headers.insert(DATE, datetime.to_rfc2822().parse().unwrap());
    headers.insert(
        HeaderName::from_static("x-amz-date"),
        datetime.format(LONG_DATE).to_string().parse().unwrap(),
    );
    headers.insert(
        HeaderName::from_static("x-amz-request-route"),
        obj_ctx.output_route.parse().unwrap(),
    );
    headers.insert(
        HeaderName::from_static("x-amz-request-token"),
        obj_ctx.output_token.parse().unwrap(),
    );
    headers.insert(HeaderName::from_static("x-amz-content-sha256"), _sha.parse().unwrap());

    if let Some(session_token) = creds.session_token {
        headers.insert(
            HeaderName::from_static("x-amz-security-token"),
            session_token.to_string().parse().unwrap(),
        );
    } else if let Some(security_token) = creds.security_token {
        headers.insert(
            HeaderName::from_static("x-amz-security-token"),
            security_token.to_string().parse().unwrap(),
        );
    }

    let s_key = signing_key(&datetime, &secret_key, &region, "s3-object-lambda");

    let canonical_request = canonical_request("POST", &_url, &headers, &_sha);
    println!("Canonical Request: {}", &canonical_request);

    let string_to_sign = string_to_sign(&datetime, &region, &canonical_request);
    println!("String to sign: {}", &string_to_sign);

    let mut hmac = HmacSha256::new_varkey(&s_key?).map_err(|e| anyhow! {"{}",e})?;
    hmac.update(string_to_sign.as_bytes());

    let signed_header = signed_header_string(&headers);

    let signature = hex::encode(hmac.finalize().into_bytes());

    let auth_header = authorization_header(&access_key, &datetime, &region, &signed_header, &signature);

    headers.insert(AUTHORIZATION, auth_header.parse().unwrap());

    let res = client.post(&url).body(vec).headers(headers).send().await?;

    println!("status-code: {}", res.status());
    println!("response: {:?}", res.text().await?);

    // prepare the response
    let resp = Response {
        req_id: ctx.request_id,
        msg: format!("Query executed."),
    };

    // return `Response` (it will be serialized to JSON automatically by the runtime)
    Ok(resp)
}
