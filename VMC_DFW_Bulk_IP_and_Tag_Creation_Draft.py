
## Future Job Get SDDC ID dynamically
import requests,csv,json

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from key import *
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


##Creating Payload , use when need to create or update something in VMC

def login():
    key = '0TGgFqjFYWkDeDU6qnN8t0Drbwdl1H3c3PeJ4dalTSOEE1ucNQLx7s9hpzw1Ns6e'
    baseurl = 'https://console.cloud.vmware.com/csp/gateway'
    uri = '/am/api/auth/api-tokens/authorize'
    headers = {'Content-Type':'application/json'}
    payload = {'refresh_token': key}
    r = requests.post(f'{baseurl}{uri}', headers = headers, params = payload)
    if r.status_code != 200:
        print(f'Unsuccessful Login Attmept. Error code {r.status_code}')
    else:
        print('Login successful. ')
    auth_header = r.json()['access_token']
    finalHeader = {'Content-Type':'application/json','csp-auth-token':auth_header}
    #print(auth_header)
    return finalHeader



def sddc_baseurl(finalHeader):
    ## Getting Org ID
    req = requests.get('https://vmc.vmware.com/vmc/api/orgs', headers = finalHeader)
    orgID = req.json()[0]['id']
    baseurl = f'https://nsx-3-9-59-86.rp.vmwarevmc.com/vmc/reverse-proxy/api/orgs/{orgID}/sddcs/9728b0cc-2b30-4715-9f26-42e94f55eb0d/'
    #return baseurl
    #print(baseurl)
    return baseurl
## Getting Org ID



#################################################################################
##### Creating Groups for IPSET or



def groups_uri (baseurl,group_name=None):
    group_uri =f'policy/api/v1/infra/domains/cgw/groups/{group_name}'
    #group_uri =f'policy/api/v1/infra/domains/cgw/groups/' # For gettting all the groups details
    #section_uri = 'policy/api/v1/infra/domains/cgw/security-policies'  ## This will replace above in future
    url = baseurl+group_uri
    #print (url)
    return url

## Creating IP base object group
def IP_Group_PayloadTemplate(IP_Groups=False, IP_Groups_Name=False):
    IPgroup_payload = {
                        "expression" :
                        [
                            {
                              "resource_type" : "IPAddressExpression",
                              #"marked_for_delete" : false,
                              #"ip_addresses" : [ "1.2.3.4/32","22.2.3.4" ],
                              "ip_addresses" : IP_Groups,
                              "_protection" : "NOT_PROTECTED"
                            }
                         ],
                        "description": IP_Groups_Name,
                        "display_name": IP_Groups_Name
                        }
    return IPgroup_payload

## function to generate Tag_Group teamplate. Currently support only one tag condition , Doesn't support two tag
def Tag_Group_PayloadTemplate(tag_groups=False, tag_groups_name=False):
    group_tag_payload = {
                            "expression": [
                              {
                                "member_type": "VirtualMachine",
                                "value": tag_groups[0],
                                "key": "Tag",
                                "operator": "EQUALS",
                                "resource_type": "Condition"
                              }
                            ],
                            "description": tag_groups_name,
                            "display_name": tag_groups_name
                            }
    return group_tag_payload




def IP_objects(objectType=[]):
  objects = []
  #print(objectType)
  for ip in objectType:
      data=f"{ip}"
      #print (data)
      objects.append(data)
  #print (objects)
  return objects

### function to create ip objects groups...
def main_ip_groups(baseurl):
    reader = csv.DictReader(open("ipgroups.csv"))
    #section_name = input("Enter Rule Section Name : ")
    for raw in reader:
        #print(raw)
        print ("\nGenerating payload for IP groups ..\n ")
        ipgroupname = raw['groupname']
        ip_group = raw['group_ip']
        ip_group_list = ip_group.split(',')
        IP_Group_SETS = IP_objects(objectType=ip_group_list)
        print(IP_Group_SETS)
        data = IP_Group_PayloadTemplate(IP_Groups=IP_Group_SETS, IP_Groups_Name=ipgroupname)
        # data,url = payload(rulename,sources,destinations,services,baseurl=baseurl,
        #             section_name = section_name ,category="Application")
        data_payload = json.dumps(data)
        #print (data_payload)
        # print(f"Creating Current Rule {rulename}.........")
        url=groups_uri(baseurl=baseurl,group_name=ipgroupname)
        #print (url)
        put_response = requests.patch(url=url, data = data_payload, headers = finalHeader)
        put_response
        if put_response.status_code !=200:
          print ("\nError Occured, One of the object doesn't exist, Check the response below", put_response.status_code)
          print (put_response.text)
        else:
            print("\nIP Groups created/Updated successfully. HTTP Response:" , put_response.status_code)
            print (put_response.text)

### function to create ip objects groups...
def main_tag_groups(baseurl):
    reader = csv.DictReader(open("taggroups.csv"))
    #section_name = input("Enter Rule Section Name : ")
    for raw in reader:
        #print(raw)
        print ("\nGenerating payload for Tag Groups..\n ")
        tag_group_name = raw['group_name']
        group_tag = raw['group_tag']
        tag_group_list = group_tag.split(',')
        tag_group_sets = IP_objects(objectType=tag_group_list)
        print(tag_group_sets)
        data = Tag_Group_PayloadTemplate(tag_groups=tag_group_sets, tag_groups_name=tag_group_name)
        # data,url = payload(rulename,sources,destinations,services,baseurl=baseurl,
        #             section_name = section_name ,category="Application")
        #print (data)
        data_payload = json.dumps(data)
        #print (data_payload)
        # print(f"Creating Current Rule {rulename}.........")
        url=groups_uri(baseurl=baseurl,group_name=tag_group_name)
        #print (url)
        put_response = requests.patch(url=url, data = data_payload, headers = finalHeader)
        put_response
        if put_response.status_code !=200:
          print ("\nError Occured, One of the object doesn't exist, Check the response below", put_response.status_code)
          print (put_response.text)
        else:
            print("\nTag Groups created/Updated successfully. HTTP Response:" , put_response.status_code)
            print (put_response.text)


if __name__=="__main__":
    finalHeader=login()
    baseurl = sddc_baseurl(finalHeader)
    choice = input("Enter 1 for creating IP Groups or 2 for creating Tag Groups or type 'all' : ")
if choice == "1":
    print(choice, "you have selected IP group, Creating IP Groups from File")
    main_ip_groups(baseurl)
elif choice =="2":
    print (choice, "you have selected Tag group,Creating Tag Groups from file")
    main_tag_groups(baseurl)
elif choice =='all' or "ALL" or "All":
    print (choice, "you have selected ALL,Creating IP/Tag Groups from file")
    print ("Creating IP Groups now.......")
    main_ip_groups(baseurl)
    print ("IP Groups Processed")
    print ("Creating Tag Groups now.......")
    main_tag_groups(baseurl)
    print ("Tag Groups Processed")
else:
    print("Wrong Numbers/Choice entered, Please run again")










#
#
#
#
# --------------------------------------------
#
#
# payload = json.dumps(IPgroup_payload)
# group_url = groups_uri (baseurl,group_name='test_ip_1.2.3.4')
# put_response = requests.put(url=group_url, data = payload, headers = finalHeader)
# print(put_response.text)
#
#
# #### Creating Tag base group object
#
#
#
#
# payload = json.dumps(group_tag_payload)
# group_url = groups_uri (baseurl,group_name='test_vm_tag2')
# put_response = requests.put(url=group_url, data = payload, headers = finalHeader)
# print(put_response.text)
# ## Example for patching existing group. Here payload was updated with 22.2.3.4 IP address in payload
# patch_response = requests.patch(url=group_url, data = payload, headers = finalHeader)
# print(patch_response.text)
#
# ####### Optional for getting groups related entrie-------------------------------------------------
#
# # def groups_uri (baseurl,group_name=False):
# #     group_uri =f'policy/api/v1/infra/domains/cgw/groups/{group_name}'
# #     #group_uri =f'policy/api/v1/infra/domains/cgw/groups/' # For gettting all the groups details
# #     #section_uri = 'policy/api/v1/infra/domains/cgw/security-policies'  ## This will replace above in future
# #     url = baseurl+group_uri
# #     #print (url)
# #     return url
# #
# # #### for getting specific group id details
# # GET https://<policy-mgr>/policy/api/v1/infra/domains/cgw/groups
# # group_url = groups_uri (baseurl,group_name='PDT.OV3.WEB.UAT')
# # get_response = requests.get(url=group_url,headers=finalHeader)
# # print(get_response.text)
#
# ************************************
# ### Creating Section for firewall rules and entires
#
# def section_uri (baseurl,section_name=None):
#     section_uri =f'policy/api/v1/infra/domains/cgw/communication-maps/{section_name}'
#     #section_uri = 'policy/api/v1/infra/domains/cgw/security-policies'  ## This will replace above in future
#     url = baseurl+section_uri
#     #print (url)
#     return url
#
#
#
# section_payload = {
#                       "resource_type": "CommunicationMap",
#                       "description": "comm map",
#                       "id": "TEST_RULE_Section2",
#                       "display_name": "TEST_RULE2_Section2",
#                       # "path": "/infra/domains/cgw/communication-maps/TEST_RULE",
#                       # "parent_path": "/infra/domains/",
#                       # "relative_path": "TEST_RULE",
#                      "communication_entries": [
#                                               {
#                                                 "description": " test_rule1",
#                                                 "display_name": "test_rule1",
#                                                 "sequence_number": 1,
#                                                 "source_groups": [
#                                                   "/infra/domains/cgw/groups/test_ip_1.2.3.4",
#                                                   #"/infra/domains/cgw/groups/test_vm_tag" ## for adding multiple groups
#                                                 ],
#                                                 "destination_groups": [
#                                                   "/infra/domains/cgw/groups/test_ip_1.2.3.4",
#                                                   # "/infra/domains/cgw/groups/test_ip_1.2.3.4"
#                                                 ],
#                                                 "services": [
#                                                   "/infra/services/HTTPS"
#                                                   #"/infra/services/HTTPS",
#                                                 ],
#                                                 "action": "ALLOW"
#                                               },
#                                               # }
#                                             ],
#
#                       "category": "Application",
#                     }
#
# payload = json.dumps(section_payload)
# section_url = section_uri (baseurl,section_name='TEST_RULE2_Section2')
# put_response = requests.put(url=section_url, data = payload, headers = finalHeader)
# print(put_response.text)
# ######
#
# ##Getting Complete Section details with rule
# section_url = section_uri (baseurl,section_name='TEST_RULE2_Section2')
# get_response = requests.get(url=section_url,headers=finalHeader)
# print(get_response.text)
#
# ## Delete section and all the rules.
# section_url = section_uri (baseurl,section_name='TEST_RULE2_Section2')
# delete_response = requests.delete(url=section_url,headers=finalHeader)
# print(delete_response.text)
