This directory contains a Go application that acts as a HEART compliant OpenID Connect relying party.
It is purely a demonstration application.

This application makes a few assumptions:
* The [MITREid Connect Server](https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server) is running on localhost:8080
* The MITREid Connect Server is configured to run on HEART mode
* This client has been registered with the MITREid Connect Server. Client ID is set to "simple". Redirect URI is set to "http://localhost:3333/redirect".
Credentials are set to "Asymmetrically-signed JWT assertion" and the key included in publickey_set.json is added. 

This application simply takes the necessary action to authenticate the user with the OpenID Connect OP. It then fetches the information
about the user from the user info endpoint and sets them up in the session. The application runs on
localhost:3333.
