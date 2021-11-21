mod core;
use reqwest::Url;
use std::io;

#[tokio::main]
async fn main() {
    let url = "https://dracoon.team";

    let base_url = Url::parse(url).unwrap();

    let client_id = "XXXXXXXXXXXXXXXXXXXXXXXXXX";
    let client_secret = "XXXXXXXXXXXXXXXXXXXXXXXXXX";

    let mut dracoon =
        core::DRACOONClient::new(base_url, client_id.to_string(), client_secret.to_string());

    let username = "XXXXXXXXXXXXXXXXXXXXXXXXXX".to_string();
    let password = "XXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(); // or fetch credentials via read_line, see beelow auth code example

    // this shows how to authenticate via password flow
    let res = dracoon
        .connect(
            core::OAuth2ConnectionType::PasswordFlow(username, password)
        )
        .await;

    println!("{:?}", res);

    // this shows how to test the established connection (returns bool)
    let conn1 = dracoon.test_connection().await.unwrap();
    println!("Connected: {}", conn1);

    let access_token_valid = dracoon.check_access_token_validity().unwrap();
    println!("Valid token: {}", access_token_valid);

    // disconnect the client (returns instance of self, therefore reassigning)
    let mut dracoon = dracoon.disconnect(Some(false)).await.unwrap();

    // use refresh token to get fresh valid access token
    let res2 = dracoon
        .connect(core::OAuth2ConnectionType::RefreshToken)
        .await;

    println!("{:?}", res2);

    let conn2 = dracoon.test_connection().await.unwrap();
    println!("Connected: {}", conn2);


    /// this shows how to authenticate via authorization code (requires OAuth app to use correct redirect uri and auth code flow!)
    println!("Get authorization code here: \n {}", dracoon.get_code_url());
    let mut auth_code = String::new();
    std::io::stdin()
        .read_line(&mut auth_code)
        .expect("Error parsing user input (auth code).");

    let res3 = dracoon
        .connect(
            core::OAuth2ConnectionType::AuthCode(auth_code.trim_end().to_string())
        )
        .await;

    println!("{:?}", res3);

    let conn3 = dracoon.test_connection().await.unwrap();
    println!("Connected: {}", conn3);
}
