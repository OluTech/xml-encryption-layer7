var crypto = require('crypto');
var async = require('async');
var xmldom = require('xmldom');
var xpath = require('xpath');
var utils = require('./utils');
var constant = require('constants');
var pki = require('node-forge').pki;
var fs = require('fs');
var fn = require('../../../lib/functions');
var id = random(20);
var encryptedDataId = 'ED-' + id + fn.random(1000, 9999);
var binarySecurityTokenId = id + fn.random(1000, 9999);
var encryptionKeyId = 'EK-' + id + fn.random(1000, 9999);

function encryptKeyInfoWithScheme(symmetricKey, options, scheme, callback) {
  var rsa_pub = pki.publicKeyFromPem(options.rsa_pub);
  var encrypted = rsa_pub.encrypt(symmetricKey.toString('binary'), scheme);
  var base64EncodedEncryptedKey = new Buffer(encrypted, 'binary').toString('base64'); 
  var ReferenceToBinarySecurityToken = createReferences(binarySecurityTokenId);
  var ReferenceToEncryptedData = createReferences(encryptedDataId);
  var binarySecurityTokenId2 = id + fn.random(1000, 9999);
  var params = {
    encryptedKey: base64EncodedEncryptedKey,
    encryptionPublicCert: utils.pemToCert(options.pem.toString()),
    keyEncryptionMethod: options.keyEncryptionAlgorithm,
    binarySecurityTokenId: binarySecurityTokenId,
    ReferenceToBinarySecurityToken: ReferenceToBinarySecurityToken,
    encryptionKeyId: encryptionKeyId,
    binarySecurityTokenId2: binarySecurityTokenId2,
    ReferenceToEncryptedData: ReferenceToEncryptedData

  };
  //var result = utils.renderTemplate('keyinfo', params);
  return callback(null, params);
}

function encryptKeyInfo(symmetricKey, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!options.rsa_pub)
    return callback(new Error('must provide options.rsa_pub with public key RSA'));
  if (!options.pem)
    return callback(new Error('must provide options.pem with certificate'));

  if (!options.keyEncryptionAlgorithm)
    return callback(new Error('encryption without encrypted key is not supported yet'));

  switch (options.keyEncryptionAlgorithm) {
    case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
      return encryptKeyInfoWithScheme(symmetricKey, options, 'RSA-OAEP', callback)

    case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
      return encryptKeyInfoWithScheme(symmetricKey, options, 'RSAES-PKCS1-V1_5', callback)

    default:
      return callback(new Error('encryption key algorithm not supported'));
  }
}

function encrypt(content, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!content)
    return callback(new Error('must provide content to encrypt'));
  if (!options.rsa_pub)
    return callback(new Error('rsa_pub option is mandatory and you should provide a valid RSA public key'));
  if (!options.pem)
    return callback(new Error('pem option is mandatory and you should provide a valid x509 certificate encoded as PEM'));

  options.input_encoding = options.input_encoding || 'utf8';

  async.waterfall([
    function generate_symmetric_key(cb) {
      switch (options.encryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
          crypto.randomBytes(16, cb); // generate a symmetric random key 16 bytes length
          break;
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
          crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
          break;
        case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
          crypto.randomBytes(24, cb); // generate a symmetric random key 24 bytes (192 bits) length
          break;
        default:
          crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
      }
    },
    function encrypt_content(symmetricKey, cb) {
      switch (options.encryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':        
          encryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
            if (err) return cb(err);
            cb(null, symmetricKey, encryptedContent);
          });
          break;
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
          encryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
            if (err) return cb(err);
            cb(null, symmetricKey, encryptedContent);
          });
          break;
        case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
          encryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, content, options.input_encoding, function (err, encryptedContent) {
            if (err) return cb(err);
            cb(null, symmetricKey, encryptedContent);
          });
          break;
        default:
          cb(new Error('encryption algorithm not supported'));
      }
    },
    function encrypt_key(symmetricKey, encryptedContent, cb) {
      var referenceToEncryptedKey = createReferences(encryptionKeyId);
      encryptKeyInfo(symmetricKey, options, function (err, keyinfo) {
        if (err) return cb(err);
        var result = utils.renderTemplate('encrypted-key', {
          encryptedContent: encryptedContent.toString('base64'),
          binarySecurityTokenId: binarySecurityTokenId,
          referenceToEncryptedKey: referenceToEncryptedKey,
          encryptedDataId: encryptedDataId,
          contentEncryptionMethod: options.encryptionAlgorithm,
          encryptedKey: keyinfo.encryptedKey,
          encryptionPublicCert: keyinfo.encryptionPublicCert,
          keyEncryptionMethod: keyinfo.keyEncryptionMethod,
          ReferenceToBinarySecurityToken: keyinfo.ReferenceToBinarySecurityToken,
          encryptionKeyId: keyinfo.encryptionKeyId,
          binarySecurityTokenId2: keyinfo.binarySecurityTokenId2,
          ReferenceToEncryptedData: keyinfo.ReferenceToEncryptedData
        });
        cb(null, result);
      });
    }
  ], callback);
}

function decrypt(xml, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!xml)
    return callback(new Error('must provide XML to encrypt'));
  if (!options.key)
    return callback(new Error('key option is mandatory and you should provide a valid RSA private key'));
  
  var decrypted;

  try {
    var doc = new xmldom.DOMParser().parseFromString(xml);

    var symmetricKey = decryptKeyInfo(doc, options);
    //var encryptionMethod = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
    //var encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');
    var encryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    var decipher;
    var padding;
    //var encryptedContent = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];
    var encryptedContent = xpath.select("//*[local-name(.)='EncryptedData']", doc)[0];    
    var encrypted = new Buffer(encryptedContent.textContent, 'base64');
    

    switch (encryptionAlgorithm) {
      case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
        decipher = crypto.createDecipheriv('aes-128-cbc', symmetricKey, encrypted.slice(0, 16));
        decipher.setAutoPadding(false);
        decrypted = decipher.update(encrypted.slice(16), null, 'binary') + decipher.final('binary');

        // Remove padding bytes equal to the value of the last byte of the returned data.
        padding = decrypted.charCodeAt(decrypted.length - 1);
        if (1 <= padding && padding <= 16) {
          decrypted = decrypted.substr(0, decrypted.length - padding);
        } else {
          callback(new Error('padding length invalid'));
          return;
        }
        
        decrypted = new Buffer(decrypted, 'binary').toString('utf8');
        break;
      case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
        decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, encrypted.slice(0, 16)); 

        //decipher.setAutoPadding(false);
        decrypted = decipher.update(encrypted.slice(16), null, 'binary') + decipher.final('binary');

        // Remove padding bytes equal to the value of the last byte of the returned data.
        padding = decrypted.charCodeAt(decrypted.length - 1);
        if (1 <= padding && padding <= 16) {
          decrypted = decrypted.substr(0, decrypted.length - padding);
        } else {
          callback(new Error('padding length invalid'));
          return;
        }
        decrypted = new Buffer(decrypted, 'binary').toString('utf8');
        break;
      case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
        decipher = crypto.createDecipheriv('des-ede3-cbc', symmetricKey, encrypted.slice(0,8)); 
        decrypted = decipher.update(encrypted.slice(8), null, 'binary') + decipher.final('binary');
        decrypted = new Buffer(decrypted, 'binary').toString('utf8');
        break;
      default:
        return callback(new Error('encryption algorithm ' + encryptionAlgorithm + ' not supported'));
    }
  } catch (e) {
    return callback(e);
  }
  
  callback(null, decrypted);
}

function decryptKeyInfo(doc, options) {
  if (typeof doc === 'string') doc = new xmldom.DOMParser().parseFromString(doc);

  var keyInfo = xpath.select("//*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
  //var keyEncryptionMethod = xpath.select("//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']", doc)[0];
  //var keyEncryptionAlgorithm = keyEncryptionMethod.getAttribute('Algorithm');
  var keyEncryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
  var encryptedKey = xpath.select("//*[local-name(.)='CipherValue']", keyInfo)[0];
  switch (keyEncryptionAlgorithm) {
    case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':      
      return decryptKeyInfoWithScheme(encryptedKey, options, 'RSA-OAEP')
    case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':      
      return decryptKeyInfoWithScheme(encryptedKey, options, 'RSAES-PKCS1-V1_5')    
    default:
      throw new Error('key encryption algorithm ' + keyEncryptionAlgorithm + ' not supported');
  }
}

function decryptKeyInfoWithScheme(encryptedKey, options, scheme) {
  var key = new Buffer(encryptedKey.textContent, 'base64').toString('binary');
  var private_key = pki.privateKeyFromPem(options.key);
  var decrypted = private_key.decrypt(key, scheme);
  return new Buffer(decrypted, 'binary');
}

function encryptWithAlgorithm(algorithm, symmetricKey, ivLength, content, encoding, callback) {
  // create a random iv for algorithm
  crypto.randomBytes(ivLength, function(err, iv) {
    if (err) return callback(err);    
    var cipher = crypto.createCipheriv(algorithm, symmetricKey, iv); 
    // encrypted content
    var encrypted = cipher.update(content, encoding, 'binary') + cipher.final('binary');
    return callback(null, Buffer.concat([iv, new Buffer(encrypted, 'binary')]));
  });
}




/**
 * Generate the Reference nodes (as part of the encryption process)
 *
 */
function createReferences(id) {
  var res = "#" + id;
  return res;
};


function random(size) {
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var random = '';
  for (var i = 0; i < size; i++) {
    random += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return random;
};



exports = module.exports = {
  decrypt: decrypt,
  encrypt: encrypt,
  encryptKeyInfo: encryptKeyInfo,
  decryptKeyInfo: decryptKeyInfo
};
