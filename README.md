
This repository holds a branch of the [Certificate Transparency](https://www.certificate-transparency.org/) (CT) Go code. It includes Trillian Preview Personality that allows trusted Certificate Authorities to publish the following:

 - certificates for preview before they become valid
 - complaints about any certificates in the log
 - resolutions of the complaints

The structure of the repository and how to build the code remain the same as the original [Certificate Transparency](https://github.com/google/certificate-transparency-go) repository. However, since the original package names have not been changed, it is required to relocate the local location of this go package from "..github.com/tienthanh411/certificate-transparency-preview" to "..github.com/google/certificate-transparency-go".

## Trillian Preview Personality

The `trillian/` subdirectory holds code and scripts for running a CT Log based
on the [Trillian](https://github.com/google/trillian) general transparency Log.

The main code for the Preview personality is held in `trillian/preview`; this code
responds to HTTP requests on the
[CT API paths](https://tools.ietf.org/html/rfc6962#section-4) and the following new paths:

- POST https://\<log server\>/ct/v1/add-complaint
- POST https://\<log server\>/ct/v1/add-resolution

More information about this personality can be found [here](https://docs.google.com/document/d/1FkwrqNcB4q0CLIPWh0Sq0dRbHruGuRyQ6MDW3efvC88/edit#)