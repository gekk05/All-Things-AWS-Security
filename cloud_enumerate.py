#TODO  Add returns for findings for each function call
#TODO  For lambda check, add a dictionary of words to check if they exist in environment variables
#TODO Work on DDB and EC2 tomorrow. 
#TODO add RDS SSE 
#TODO Figure out how it will work with multiple accounts, seems now it's being passed in via env variables
#TODO anaylis on bucket object contents, check for stuff like exexc
#TODO fix SQS,SNS. The try,catch is shitty 
#TODO FIX cloudtrail. describe_trails to check for logging validation and such, this shit is annoying. supposed to take a list, but not taking
#TODO FIX ELb
#TODO consider porting to a db..
#TODO Userdatas for ec2 instances?

import boto3
import json
import logging
import colorama
import socket 
from colorama import Fore, Style, init
init(autoreset=True)
#region = "us-east-1"

print(Fore.CYAN + r"""


#Calculate length of string to stdout from the pritn statement for the "account number: " identity call and add that to the length of the stdout string from all the services
#def logging_config(): 
#logging.basicConfig(filename='loggingtest.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s:%(message)s')
#formatter = logging.Formatter(
#logger.addHandler(add something here
#
#Default level of logging is set to warning, so levels under will not be shown in stdout. (INFO and DEBUG) which are important. We need to set it lower
 

def divider(): 
 print("\n" + Fore.CYAN + "="*150) 

def multiple_service_divider(): 
 print(Fore.CYAN + "-"*150)

divider()
identity = boto3.client('sts').get_caller_identity()
logger.info(Style.DIM + " Account number: " + identity["Account"]) 
#print(Style.DIM + "Account number: " + identity["Account"])

session = boto3.session.Session()
active_Services = session.get_available_resources() # returns a list of active services 
divider() 
print("Active services on the account: ") 
for services in active_Services: 
 print(Style.BRIGHT + Fore.CYAN + "[" + str(services).upper() + "]", end=" ")

#session = boto3.Session(profile_name='dev')

def s3_check(): 
 divider()
 print(Style.BRIGHT + Fore.CYAN + "[S3 ENUMERATION]") 
 loggingCount = 0
 versioningCount = 0 
 encryptionCount = 0 

 s3 = boto3.resource('s3') 
 s3client = boto3.client('s3') #need the client for access to more stuff like encryption

#Returns and logic: 
# s3.BucketLogging(buckets.name).logging_enabled) returns "None" if logging is not enabled
# s3.BucketVersioning(buckets.name).status returns "None" if versioning is not enabled
# s3client.get_bucket_encryption(Bucket=buckets.name) throws an exception if SSE is not enabled.


 for buckets in s3.buckets.all():
  #for objects in s3.object(buckets.name, key) // Check object level recursicely for SSE attritubres 
 # logger.info(" Bucket:  " + buckets.name) 
  multiple_service_divider()
  if(str(s3.BucketLogging(buckets.name).logging_enabled) == "None"):
   logger.info(" Bucket: " + Style.BRIGHT + buckets.name + Style.RESET_ALL +  Fore.MAGENTA + " Server Access Logging DISABLED")
   loggingCount += 1
  if(str(s3.BucketVersioning(buckets.name).status) == "None"):
   versioningCount += 1
   logger.info(" Bucket: " +  Style.BRIGHT + buckets.name  + Style.RESET_ALL +  Fore.MAGENTA +  " Versioning DISABLED")
   #generate_S3Report(bucket name)
  try: 
   s3client.get_bucket_encryption(Bucket=buckets.name)
  except Exception as e: 
   encryptionCount += 1
   logger.info(" Bucket: " + Style.BRIGHT +  buckets.name + Style.RESET_ALL +  Fore.MAGENTA  + " Server Side Encryption DISABLED")   
  try:
   logging.info(s3.BucketPolicy(buckets.name).policy) #when we get more test cases, later test how to evaluate a found policy 
  except Exception as e: 
   logger.info(" Bucket: " + Style.BRIGHT + buckets.name + Style.DIM + " No bucket policy")
  try: 
   s3.BucketCors(buckets.name).cors_rules
  except Exception as e: 
   logger.info(" Bucket: " + Style.BRIGHT + buckets.name + Style.DIM +  " No CORS configuration")
  #print(s3.BucketAcl(buckets.name).owner)




 print(Style.DIM + Fore.CYAN + "TOTAL FINDINGS:", loggingCount + versioningCount + encryptionCount)
#print(s3client.get_bucket_encryption(Bucket=buckets.name))
   #print(+ Fore.MAGENTA + " SSE DISABLED")
#logging disabled, returns 'none' ?
#error when SSE isn't found 

def SQS_Check():


 divider() 
 print(Style.BRIGHT + Style.BRIGHT + Fore.CYAN + "[SQS ENUMERATION]") 
#add TLS check on endpoints 	
 sqsClient = boto3.client('sqs') 
 queues = sqsClient.list_queues()
 for qs in queues['QueueUrls']: 
#  print(type(sqsClient.get_queue_attributes(QueueUrl=qs, AttributeNames=['KmsMasterKeyId'])))
  sse = sqsClient.get_queue_attributes(QueueUrl=qs, AttributeNames=['KmsMasterKeyId'])
  try:
   sse["Attributes"] 
  except Exception as e: 
   logger.info(" Queue " + qs + Fore.MAGENTA + " Server Side Encryption DISABLED")
#checking keys here, if kms key doesn't exist, SEE is disabled

#queues['QueueUrls']
#for queues in sqsClient.list_queues(): #grab the queue names

 

def SNS_Check():
 snsClient = boto3.client('sns')
#over-permissive SNS topics https://www.cloudconformity.com/knowledge-base/aws/SNS/sns-topic-exposed.html#
#why the FUCK does the attribute getter for SNS not have an AttributeNames parameter like SQS does??
#Totally rewrite this logic... terrible. the try, catch is terrible. also, for loops aren't looped propely. getting duplicates
 divider() 
 print(Style.BRIGHT + Fore.CYAN + "[SNS ENUMERATION]") 
 for topics in snsClient.list_topics()["Topics"]: 
  attributes = snsClient.get_topic_attributes(TopicArn=topics["TopicArn"])
  try: 
   attributes["Attributes"]["KmsMasterKeyId"] #exception will be thrown if SEE is disabled 
  except Exception as e: 
   logger.info(" Topic " + topics["TopicArn"] + Fore.MAGENTA + " Server Side Encryption DISABLED") 
   if '"Principal":{"AWS":"*"' in attributes["Attributes"]["Policy"]:
    logger.info(attributes["Attributes"]["Policy"]) 
    multiple_service_divider() 
    logging.info(" Topic " + topics["TopicArn"]  + Fore.MAGENTA + " over-permissive principal policy [WILDCARDED] ") 
 



   #print(attributes["Attributes"]["Policy"])  
#  lol = attributes["Attributes"]["Policy"]
 # for x in lol: 
  # print(x.keys())  
#KMS is returned in dict when encryption is enabled

   
#arn = snsClient.list_topics()["Topics"] #returns a list
#  print(arn[0])
#print(type(active_Topics)) 


#GetTopicAttributes


 #for topics in snsClient.list_topics(): 
  #print(topics)

def cloudFront_Check(): 
 divider() 
 print(Style.BRIGHT + Fore.CYAN + "[ClOUDFRONT ENUMERATION]") 
 cloudfront = boto3.client('cloudfront')
 distr = cloudfront.list_distributions()["DistributionList"] 
 for items in distr["Items"]:
  ids = cloudfront.get_distribution_config(Id=items["Id"])
  config = ids["DistributionConfig"]
  if config["Logging"]["Enabled"] == False: 
   logging.info(" " + items["ARN"] + Fore.MAGENTA + " LOGGING DISABLED")
  if config["DefaultCacheBehavior"]["ViewerProtocolPolicy"] != "https-only":
   logging.info(" " + items["ARN"] + Fore.MAGENTA + " is NOT HTTPS ONLY") 


def cloudWatch_Check(): 
 cloudwatch = boto3.client('logs')
 #read in from dictionary of stuff we'd look for tht may entail customer info 
 #aws auth token headers, etc 
 #this is extreemly flawed and lazy, fi xthis
 #can create analysis into an independent method and also use it to analyze clodutrail streams
 divider()
 print(Style.BRIGHT + Fore.CYAN + "[CLOUDWATCH ENUMERATION]") 
 with open("aws_words") as wordlist:
  words = wordlist.read().splitlines() 
 logging.info(" Beginning static analysis of CloudWatch log streams")
 for groups in cloudwatch.describe_log_groups()["logGroups"]: 
  for streams in cloudwatch.describe_log_streams(logGroupName=groups["logGroupName"], orderBy='LastEventTime')["logStreams"]: 
   for badword in words: 
    if badword in str(cloudwatch.get_log_events(logGroupName=groups["logGroupName"], logStreamName=streams["logStreamName"], startFromHead=False)): 
     logging.info( " Log Group " + Style.BRIGHT +  groups["logGroupName"] + Style.RESET_ALL + " stream " + Style.BRIGHT + streams["logStreamName"] + Style.RESET_ALL + " found interesting log containing " +  Fore.MAGENTA + "'" + badword + "'")    
 


def cloudTrail_check():
 cloudtrail = boto3.client('cloudtrail')
 for trails in cloudtrail.list_trails()["Trails"]:
  if cloudtrail.get_trail_status(Name=trails["Name"])["IsLogging"] == False: 
   divider() 
   print(Style.BRIGHT + Fore.CYAN + "[CLOUDTRAIL ENUMERATION]")
   logging.info(Style.BRIGHT + " Log trail "  + str(trails["Name"]) + Style.RESET_ALL + Fore.MAGENTA + " LOGGING DISABLED")
  #print(cloudtrail.describe_trails(trailNameList=cloudtrail.list_trails()["Trails"]))  




def iam_Check(): 
 divider() 
 print(Style.BRIGHT + Fore.CYAN + "[IAM ENUMERATION]") 
 iam = boto3.client('iam') 
 #iamc = boto3.resource('iam') 
 #print(iamc.RolePolicy('AWSLambdaBasicExecutionRole-e388c669-8077-4a20-8141-3297421123d7', 'test-role-3nyx1uem').policy_document) 
# print(iam.generate_credential_report()) This includes all attempts that were made using the AWS Management Console, the AWS API through any of the SDKs, or any of the command line tools
# for policies in iam.get_account_authorization_details()["Policies"]: 
  #logging.info(policies["PolicyName"])
 attached_policies = iam.list_policies(OnlyAttached=True)["Policies"] #returns all of the policies that are attached to users, groups, or roles. this will weed out inactive managed
 for x in attached_policies:
  print(x["Arn"]) 
 
 #for x in iam.list_roles()["Roles"]: 
  #print(iam.list_role_policies(RoleName=x["RoleName"])["PolicyNames"])

 #def get_Roles():
  #for roles in iam.list_roles()["Roles"]:
   #print(iam.list_role_policies(RoleName=roles["RoleName"])) 
# get_Roles() 


def lambda_Check():
 divider()
 print(Style.BRIGHT + Fore.CYAN + "[LAMBDA ENUMERATION]") 
 lam = boto3.client('lambda') 
 for functions in lam.list_functions()["Functions"]: 
  #print(functions.keys())  
#  print(functions["FunctionName"])  worked
  if "Environment" in functions.keys(): 
   logging.info(" Environment variables found in lambda function " + Style.BRIGHT + "[" + functions["FunctionName"] + "]") 
   #logging.info(" Lambda " + functions["FunctionName"] + Fore.GREEN + " Environment variables found")  
   logging.info(Style.DIM + str(functions["Environment"]))  

 # print(type(functions["Variables"])) 
# for x in lamba.list_functions(): 
 # print(type(x))  

#add metadata version check in advanced details , metadata accessible 
#For V2 requests, you must include a session token in all instance metadata requests. Applications or agents that use V1 for instance metadata access will break.
#MetadataOptions, HttpTokens, 

#this is atrocious looking and not maintainable at all..
def ec2_Check(): 
 divider()  
 print(Style.BRIGHT + Fore.CYAN + "[EC2 ENUMERATION]") 
 ec2 = boto3.client('ec2') 
 for volumes in ec2.describe_volumes()["Volumes"]:
  for x in volumes["Attachments"]:
   id = x["VolumeId"]  
   if volumes["Encrypted"] == False: 
    logging.info(" EBS Volume " + Style.BRIGHT + id + Style.RESET_ALL + Fore.MAGENTA + " Server Side Encryption Disabled")   
 for x in ec2.describe_security_groups()["SecurityGroups"]:
  for y in x["IpPermissions"]:
   for z in y["IpRanges"]:
    if "0.0.0.0/0" in z["CidrIp"]: 
     logging.info(" Inbound rules for port " + Style.BRIGHT +  str(y["FromPort"]) + Style.RESET_ALL + " are currently set to " + Fore.MAGENTA  + str(z["CidrIp"]) + " should be scoped down")
 for reservations in ec2.describe_instances()["Reservations"]:
  for instances in reservations["Instances"]:
   if instances["MetadataOptions"]["HttpEndpoint"] == "enabled":
    if instances["MetadataOptions"]["HttpTokens"] == "optional": 
     logging.info(" Tokens sent in IMDS requests for EC2 instance ID: " + Style.BRIGHT +  str(instances["InstanceId"] + Style.RESET_ALL + " are " +  Fore.MAGENTA + "NOT ENFORCED BEING FORCED"))   
    else: 
     print("something went wrong") 
   else: 
    print("IDMS Disabled") 


# for x in ec2.describe_instances()["Reservations"]:
  #for y in x["Instances"]:
   #for z in y["SecurityGroups"]: 
    #print(z["GroupId"])   
# print(ec2.describe_instances().keys())  
 #print(instances)
 #print(type(instances)) 

#TODO complete this. 
def elb_Check(): 
 divider() 
 print(Style.BRIGHT + Fore.CYAN + "[ELB ENUMERATION]")
 elb = boto3.client('elb')
 for load_balancers in elb.describe_load_balancers()["LoadBalancerDescriptions"]:
  print(load_balancers["ResponseMetadata"])  



def main():
# logging_config() 
 if 'sns' in active_Services:
  SNS_Check()
 if 'sqs' in active_Services:
  SQS_Check() 
 if 's3' in active_Services:
  s3_check() 
 if 'rds' in active_Services: 
  RDS_Check()
 #if 'dynamodb' in active_Services: 
#  ddb_Check() 
 if 'ec2' in active_Services: 
  ec2_Check() 
 #if 'lambda' in active_Services: 	Why is labmda not in sts call? 
 lambda_Check() 
 iam_Check() 
 cloudTrail_check() 
 cloudFront_Check()
 cloudWatch_Check()
 elb_Check()  
#create print functions cus this sucks 
#we are going to list all of the services with boto3's client service and store them all in a dict. then we'll check if that service is in that dict before calling functions like sns_check() to prevent running functions against services that dont exist 
#possibly write a while() to iterate through all credentials in env variables 


main() 


