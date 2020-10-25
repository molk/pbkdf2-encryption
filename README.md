# Password Based Key Derivation in Java

The class [PBKDF2Encryption.java](src/main/java/PBKDF2Encryption.java) provides
an example implementation of _Password Based Key Derivation_ according to [RFC-2898](https://tools.ietf.org/html/rfc2898). 

PBKDF is primarily used to realize and encryption interobarable between Java and Microsoft .NET.
 
The .NET framework offers [Rfc2898DeriveBytes](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes)
often used for encryption.

This code is based on the following resources:

* [AES Encryption between Java and C#](https://mjremijan.blogspot.com/2014/08/aes-encryption-between-java-and-c.html)
  by Michael Remijan
* [Simple interoperable encryption in Java and .net](https://steelmon.wordpress.com/2013/07/01/simple-interoperable-encryption-in-java-and-net/)
  by Stellan Soderstrom
