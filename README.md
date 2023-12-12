**example wsgi script**

    import sys
    
    sys.path.insert(0, "/local/cert-app")
    
    from app import app as application

**example apache conf**

    <VirtualHost *:80>
      ServerName sucm-test.it.su.se
      RewriteEngine On
      #redirect port 80 requests
      RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]
    </VirtualHost>
    
    <VirtualHost *:443>
      ServerName sucm-test.it.su.se
    
      SSLEngine on
      SSLCertificateFile	/local/secret/ssl/cert-test-app01.it.su.se.pem
      SSLCertificateKeyFile /local/secret/ssl/cert-test-app01.it.su.se.key
      SSLCertificateChainFile /local/secret/ssl/cert-test-app01.it.su.se-cachain.crt
    
      SSLProxyProtocol all -SSLv2 -SSLv3 -TLSv1
    
      SSLProxyEngine on
    
      DocumentRoot /local/cert-app
      ErrorDocument 401 "You are missing entitlement required to use this service."
    
    
      LimitRequestLine 90000
      LimitRequestFieldSize 90000
    
      WSGIDaemonProcess sucm python-home=/local/cert-app
      WSGIProcessGroup sucm
    
      WSGIScriptAlias / /local/cert-app/sucm.wsgi
    
    
      <LocationMatch "^/">
          AuthType shibboleth
          ShibRequireSessionWith idp-test.it.su.se
          Require shib-attr memberOf it-staff
          RequestHeader set X-Remote-User %{REMOTE_USER}s
          RequestHeader set X-Remote-Display-Name %{displayName}s
          RequestHeader set X-Remote-MemberOf %{memberOf}s
      </LocationMatch>
    
    
      <Directory /opt/SUCM>
          Require all granted
      </Directory>

</VirtualHost>

**Create db tables**

    CREATE TABLE CertificateAuthority (
    CA_Id INT UNSIGNED NOT NULL,
    CA_Name TEXT NOT NULL,
    Auth_Method TEXT NOT NULL,
    PRIMARY KEY (CA_Id));
    
    INSERT INTO CertificateAuthority (CA_Id, CA_Name, Auth_Method)
    VALUES
    ('1', 'Sectigo', 'EAB'),
    ('2', 'Dummy CA', 'Returns Snakeoil');
    
    CREATE TABLE Certificate(
    Cert_Id INT UNSIGNED NOT NULL,
    CA_Id INT NOT NULL,
    Common_Name TEXT NOT NULL,
    Subject_Alt TEXT NOT NULL,
    Country TEXT NOT NULL,
    State TEXT NOT NULL,
    City TEXT NOT NULL,
    Org TEXT NOT NULL,
    Status TEXT NOT NULL,
    Type TEXT NOT NULL,
    Secret_Path TEXT NOT NULL,
    Notify_Group_Id INT NULL,
    Create_Date DATE NULL,
    Expiry_Date DATE NULL,
    PRIMARY KEY (Cert_Id));
    
    CREATE TABLE ActiveCertificate(
    ActiveCertificate_Id INT UNSIGNED NOT NULL,
    Cert_Id INT NOT NULL,
    Common_Name TEXT NOT NULL,
    Cert_PEM TEXT NOT NULL,
    Create_Date DATE NULL,
    Expiry_Date DATE NULL,
    PRIMARY KEY (ActiveCertificate_Id));
    
    CREATE TABLE NotifyGroup(
    Group_Id INT UNSIGNED NOT NULL,
    Group_Name TEXT NOT NULL,
    Email_CSV TEXT NOT NULL,
    PRIMARY KEY (Group_Id));

