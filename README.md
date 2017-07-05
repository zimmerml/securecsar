# securecsar

securecsar is a prototype built to secure TOSCA Cloud Service Archives (CSARs). The prototype is part of research work of master's thesis "Securing Cloud Service Archives for Function and Data Shipping in Industrial Environments" done at University of Stuttgart, Germany (IAAS Department). The prototype allows to provide security to TOSCA CSAR by defining policies in CSAR. The prototpye provides security to CSAR by implementing following use-cases.

1. encrypt all CSAR artifacts (default case) or individual artifacts in a CSAR
1. sign all CSAR artifacts (default case) or individual artifacts in a CSAR
1. verify all CSAR artifacts (default case) or individual artifacts in a CSAR
1. decrypt all CSAR artifacts (default case) or individual artifacts in a CSAR

The implementation of prototype consists of two projects:
1. securecsar-frontend (https://github.com/smalihaider/securecsar-frontend.git) (contains Web based GUI to call REST services)- CURRENT REPOSITORY
1. securecsar (https://github.com/smalihaider/securecsar.git) (contains services)

# securecsar (back-end application)
This project contains the following REST endpoints.

1. http://<hostname>:<port>/securecsar/encrypt
1. http://<hostname>:<port>/securecsar/sign
1. http://<hostname>:<port>/securecsar/verify
1. http://<hostname>:<port>/securecsar/decrypt

You can easily setup the securecsar project using the following steps to deploy securecsar services in a web server (only tested with tomcat 9).

1. Checkout this repository.
1. Configure "download_file_container" property in configuration file in <checkout repository path>/src/main/resources. Processed files are temporarily placed here until downloaded by the user.
1. Run "mvn package" to create securecsar.war file
1. Deploy securecsar.war on the webserver (only tested with tomcat 9).

A Web based graphical user interface to access these REST webservices is also available at https://github.com/smalihaider/securecsar-frontend.git

More information of this prototype is included in scripture of the master's thesis "Securing Cloud Service Archives for Function and Data Shipping in Industrial Environments".
