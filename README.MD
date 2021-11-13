# DRACOON-OXIDE

A minimal async DRACOON client in Rust built with
- reqwest
- tokio
- serde 

## FAQ
### What is this?
This is a minimal experimental DRACOON client written in Rust. 

### What features are available?
Currently, only login (authentication) is available – the following OAuth2 flows are supported:

- Password flow
- Authorization code
- Refresh token

The following public methods are exposed for DRACOONClient:

- connect: connect by any supported OAuth2 flow (see above)
- disconnect: revokes access token (refresh token revoke not implemented yet)
- get_code_url: returns a string to print the code URL for authorization code flow
- test_connection: checks authenticated connection via authenticated ping (GET /users/ping)

### Why?
This is a Rust learning project by building an API wrapper. The library will serve for future learning projects such as CLI tools.

### How to use?
Check out main.rs in the repo for a full working example on using the lib. 


