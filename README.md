[![Build Status](https://travis-ci.org/auth0/node-xml-encryption.png)](https://travis-ci.org/auth0/node-xml-encryption)

W3C XML Encryption Layer 7 implementation for node.js (http://www.w3.org/TR/xmlenc-core/)

**Please note this is a fork from the original xml-encryption found here: https://github.com/auth0/node-xml-encryption.git**

**This node module changes the original XML template to adhere to Computer Associate's Layer 7 Policy Manager**

## Usage

    npm install xml-encryption-layer7

### encrypt

~~~js
var xmlenc = require('xml-encryption-layer7');

var options = {
  rsa_pub: fs.readFileSync(__dirname + '/your_rsa.pub'),
  pem: fs.readFileSync(__dirname + '/your_public_cert.pem'),
  encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
};

xmlenc.encrypt('content to encrypt', options, function(err, result) { 
    console.log(result);
}
~~~

Result:
~~~xml
<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc" />
  <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
  <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" />
    <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
       <dsig:X509Data><dsig:X509Certificate>...encrypted content...</dsig:X509Certificate></dsig:X509Data>
    </dsig:KeyInfo>
    <xenc:CipherData>
      <xenc:CipherValue>...encrypted content...</xenc:CipherValue>
    </xenc:CipherData>
  </xenc:EncryptedKey>
</dsig:KeyInfo>
  <xenc:CipherData>
    <xenc:CipherValue>...encrypted content...</xenc:CipherValue>
  </xenc:CipherData>
</xenc:EncryptedData>
~~~

### decrypt

~~~js
var options = {
    key: fs.readFileSync(__dirname + '/your_private_key.key'),
};

xmlenc.decrypt('<xenc:EncryptedData ..... </xenc:EncryptedData>', options, function(err, result) { 
    console.log(result);
}

// result

decrypted content
~~~

## Supported algorithms

Currently the library supports:

* EncryptedKey to transport symmetric key using:  
  * http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
  * http://www.w3.org/2001/04/xmlenc#rsa-1_5

* EncryptedData using:  
  * http://www.w3.org/2001/04/xmlenc#aes128-cbc
  * http://www.w3.org/2001/04/xmlenc#aes256-cbc
  * http://www.w3.org/2001/04/xmlenc#tripledes-cbc

However, you can fork and implement your own algorithm. The code supports adding more algorithms easily

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.
