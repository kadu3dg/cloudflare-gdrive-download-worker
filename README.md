# Google Drive File Download API

Note: The Project can be deployed by copy pasting worker.js file, while technical knowledge is required to use it.

## Required Items to Get Started

* Use of Refresh Token with Client Credentials
* Use of Service Account
* Web Crypto API 256 bit Key
* Web Crypto API 128 bit iv

## Available Functions

* Generating Links based on File ID
* Fetching File Info based on RAW File ID
* Download Files based on RAW File ID
* Download FIles based on Time Token and Encrypted File ID
* Generate Keys to Use Encryption Process

### Generating Links API

````
https://example.com/generate.aspx?id=<DRIVEIDHERE>
````

* Add pretty=true for Pretty JSON

### Fetching File Info API

````
https://example.com/info.aspx?id=<DRIVEIDHERE>
````

* Add pretty=true for Pretty JSON

### Downloading Files API using Time Based Token

````
https://example.com/download.aspx?file=<EncryptedID>&expiry=<EncryptedExpiry>&mac=<EncryptedIntegrity>
````

### Downloading Files API using RAW File ID

````
https://example.com/direct.aspx?id=<DRIVEIDHERE>
````

### Fetching Encryption Keys Randomly

````
https://example.com/generate_web_crypto.aspx
````

#### Credits

* ChatGPT
* Cloudflare Workers
* Google Drive API
* Gitlab
* GitHub Co-Pilot
* Google Drive Index -  GDI.JS.ORG

#### Versions

* v1.0 - Basic Version Built

#### Written By

* Parveen Bhadoo with the help of ChatGPT and GitHub Co-Pilot via Google Drive API Docs