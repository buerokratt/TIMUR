[![Quality Gate Status](https://sonarqube.riaint.ee/api/project_badges/measure?project=rig-ee.eesti.timur&metric=alert_status&token=9d931b90fd0197f9fcfd743984126d8af0202b7d)](https://sonarqube.riaint.ee/dashboard?id=rig-ee.eesti.timur) [![Bugs](https://sonarqube.riaint.ee/api/project_badges/measure?project=rig-ee.eesti.timur&metric=bugs&token=9d931b90fd0197f9fcfd743984126d8af0202b7d)](https://sonarqube.riaint.ee/dashboard?id=rig-ee.eesti.timur) [![Vulnerabilities](https://sonarqube.riaint.ee/api/project_badges/measure?project=rig-ee.eesti.timur&metric=vulnerabilities&token=9d931b90fd0197f9fcfd743984126d8af0202b7d)](https://sonarqube.riaint.ee/dashboard?id=rig-ee.eesti.timur) [![Code Smells](https://sonarqube.riaint.ee/api/project_badges/measure?project=rig-ee.eesti.timur&metric=code_smells&token=9d931b90fd0197f9fcfd743984126d8af0202b7d)](https://sonarqube.riaint.ee/dashboard?id=rig-ee.eesti.timur) [![Coverage](https://sonarqube.riaint.ee/api/project_badges/measure?project=rig-ee.eesti.timur&metric=coverage&token=9d931b90fd0197f9fcfd743984126d8af0202b7d)](https://sonarqube.riaint.ee/dashboard?id=rig-ee.eesti.timur)

# TARA Integration Module (TIM) Undergone Rewrite (TIMUR)

TIMUR is TIM for Eesti.ee

# 0. Used variables description

* `${PROJECT_ROOT}` - root folder of the project

# 1. Building from source

inside project root folder `${PROJECT_ROOT}` execute the following:

```shell
./mvnw clean -U package
```

This should produce an executable jar file at following location:

`${PROJECT_ROOT}/target/timur.jar`

# 2. Configuration

Spring Boot applications support externalized configuration through *.properties and *.yml files

Configuration parameters are described in the sample configuration properties file.

## 2.1 Certificates generation

**Note!** Both keystore password and alias password should be the same.

### 2.1.1 Certificate for JWT signature

```shell
keytool -genkeypair -alias jwtsign -keyalg RSA -keysize 2048 -keystore "jwtkeystore.p12" -validity 3650 -storetype PKCS12
```

relevant configuration properties:

```properties
jwt-integration.signature.key-store=classpath:jwtkeystore.p12
jwt-integration.signature.key-store-password=ppjjpp
jwt-integration.signature.keyStoreType=PKCS12
jwt-integration.signature.keyAlias=jwtsign
```

### 2.1.2 Regenerating Certificates

To generate a new key pair with certificate:

1. backup the original keystore file.
2. run certificate generation `keytool` command from previous step(s)
3. update configuration with new keystore file and password

### 2.1.3 Changing Keystore password

To change keystore password,

1. run the following command

    ```shell
    keytool -keystore <keystore file name> -storepasswd
    # (old and new password asked)
    ```

2. update configuration with new password

## 3. Running locally (connected with GovSSO DEMO)

1. Create `${PROJECT_ROOT}/application-dev.yml` to override application properties:

    ```yaml
    server:
      port: 8443
      ssl:
        enabled: true
        key-alias: timur
        key-store: /timur-config/keystore.p12
        key-store-password: changeit
        key-store-type: PKCS12

    security:
      oauth2:
        client:
          client-id: 917ed455-623a-4773-a0fd-6a2386ab7b01
          client-secret: <VALUE_FROM_VAULT_DEV_rig/timur>
          registered-redirect-uri: https://local.arendus.eesti.ee/timur/authenticate
          default-post-logout-redirect-uri-template: https://local.arendus.eesti.ee:4200/{lang}/tagasiside
          user-authorization-uri: https://govsso-demo.ria.ee/oauth2/auth
          access-token-uri: https://govsso-demo.ria.ee/oauth2/token
          logout-uri: https://govsso-demo.ria.ee/oauth2/sessions/logout
        resource:
          jwk:
            key-set-uri: https://govsso-demo.ria.ee/.well-known/jwks.json
        provider:
          issuer-uri: https://govsso-demo.ria.ee/

    frontpage:
      redirect:
        url: https://local.arendus.eesti.ee:4200/
   
   refresh-token:
    client-secret: client-secret
    encryption-key: secret-encryptio
    client-id: client-id

    auth:
      success:
        redirect:
          whitelist:
            - https://local.arendus.eesti.ee:4200/auth/callback
            - https://local.arendus.eesti.ee:4200/ettevotja/auth/callback
    logout:
      success:
        redirect:
          whitelist:
            - https://local.arendus.eesti.ee:4200/ettevotja/et/tagasiside
            - https://local.arendus.eesti.ee:4200/ettevotja/en/tagasiside
            - https://local.arendus.eesti.ee:4200/ettevotja/ru/tagasiside

    legacy-portal-integration:
      session-cookie-domain: local.arendus.eesti.ee

    jwt-integration:
      signature:
        cookie-domain: local.arendus.eesti.ee

    logging:
      level:
        ee:
          eesti: DEBUG
    ```

2. Generate local certificate for local.arendus.eesti.ee. See [local-ssl/README.md](local-ssl/README.md)

3. Run the following commands:

    ```shell
    ./mvnw clean -U package
    docker-compose up --build
    ```

4. Route `local.arendus.eesti.ee` to `localhost` in `/etc/hosts`:

    ```code
    127.0.0.1	local.arendus.eesti.ee
    ```

5. Open https://local.arendus.eesti.ee/timur/oauth2/authorization/govsso to initiate auth via GovSSO

# 4. Redis

Exploring entries in local redis via CLI:

```shell
docker-compose exec redis redis-cli
```

```shell
keys *
smembers GovssoSession
exit
```

Exploring entries in dev environment redis via CLI (acquire password from https://vault-dev.ria.ee/ui/vault/secrets/dev/show/rig/redis):

```shell
docker-compose exec redis redis-cli --tls --insecure --user test-kasutaja --askpass -c -h rig-redis-01.dev.riaint.ee
```

```shell
keys *
smembers GovssoSession
exit
```
