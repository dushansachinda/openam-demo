# CREATE following table under AM_DB (this for mysql change per the DB type)

CREATE TABLE IF NOT EXISTS OPENAM_CLIENT (
              CLIENT_ID VARCHAR (100),
              PAYLOAD VARCHAR (2000),
             PRIMARY KEY (CLIENT_ID)
)ENGINE INNODB;

Authorize http://localhost:8080/openam/json/authenticate
Userinfo http://localhost:8080/openam/oauth2/userinfo
Revole http://localhost:8080/openam/oauth2/access_token
TokenEP http://localhost:8080/openam/oauth2/access_token
Intros http://localhost:8080/openam/frrest/oauth2/token/
Client http://localhost:8080/openam/frrest/oauth2/client/_