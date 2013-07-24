S3dropbox
---------

`s3dropbox` provides S3 Form Uploads from the command line

Status
------

[![Build Status](https://travis-ci.org/noahcampbell/s3dropbox.png?branch=master)](https://travis-ci.org/noahcampbell/s3dropbox)

Description
-----------

s3dropbox allows a file to be uploaded to S3 using the AWS Form Upload technique.  It also allows for the creation of a policy document used during the upload.

### Synopsis


Upload a file using an existing policy

		s3dropbox --policy ./upload.policy file1.ext

Upload a file using a policy hosted over http

		s3dropbox --policy http://host/path/remote.policy file1.ext

Upload a file using a policy embedded in a form on a webpage.

		s3dropbox --policy http://host/path/form file1.ext

In addition to uploading a file, s3dropbox can be used to generate a policy document.  A set of AWS credentials are required.

Create a upload policy document

		s3dropbox --expiration 2023-12-31T23:59:59.000Z --condition acl=private --condition-startswith \$key=user/upload --condition bucket=my-s3dropbox --condition-range \$content-length,1024,2048 --aws-secret-key-id=id --aws-secret-key=secret --output upload.policy 
