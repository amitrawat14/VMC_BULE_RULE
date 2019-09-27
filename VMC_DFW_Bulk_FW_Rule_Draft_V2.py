import requests,csv,json

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from key import *
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


##Creating Payload , use when need to create or update something in VMC

def login():
    key = 'Enter  your vmc account key......'
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

#finalHeader=login()

def sddc_baseurl(finalHeader):
    ## Getting Org ID
    req = requests.get('https://vmc.vmware.com/vmc/api/orgs', headers = finalHeader)
    orgID = req.json()[0]['id']
    baseurl = f'https://nsx-3-9-59-86.rp.vmwarevmc.com/vmc/reverse-proxy/api/orgs/{orgID}/sddcs/Enter SDDC ID Here..../'
    #return baseurl
    #print(baseurl)
    return baseurl
### Getting Org ID
#baseurl = sddc_baseurl(finalHeader)



##### Creation Section name and Multiple FW rules in one section

def payload (rulename,sources,destinations,services,baseurl=None,
            section_name = "TEST_RULE_Section",category="Application"):
    section_payload = {
                        "resource_type": "CommunicationMap",
                        "description": section_name,
                        "id": section_name,
                        "display_name": section_name,
                        "communication_entries": [{"description": rulename,"display_name": rulename,"sequence_number": 1,
                                               "source_groups": sources,"destination_groups": destinations,"services": services,
                                                "action": "ALLOW"},],
                                                "category": category,
                      }
    section_uri = f'policy/api/v1/infra/domains/cgw/communication-maps/{section_name}'
    url = baseurl+section_uri
    return section_payload,url




def IP_objects(objectType=[]):
  objects = []
  #print(objectType)
  for i in objectType:
      data=f"/infra/domains/cgw/groups/{i}"
      #print (data)
      objects.append(data)
  #print (objects)
  return objects

def service_objects(objectType=[]):
  objects = []
  #print(objectType)
  for i in objectType:
      data=f"/infra/services/{i}"
      #print (data)
      objects.append(data)
  #print (objects)
  return objects


def main():
    reader = csv.DictReader(open("fwrules.csv"))
    section_name = input("Enter Rule Section Name : ")
    for raw in reader:
        print ("\nGenerating payload.. ")
        rulename = raw['rulename']
        s_group = raw['source_group']
        s_group_list = s_group.split(',')
        d_group = raw['dst_group']
        d_group_list = d_group.split(',')
        srv_group = raw['service']
        srv_group_list = srv_group.split(',')
        #print(raw['rulename'],raw['source_group'],raw['dst_group'],raw['service'])
        sources = IP_objects(objectType=s_group_list)
        destinations = IP_objects(objectType=d_group_list)
        services = service_objects(objectType=srv_group_list)
        data,url = payload(rulename,sources,destinations,services,baseurl=baseurl,
                    section_name = section_name ,category="Application")
        #print("error occured")
        #print(type(data))
        data_payload = json.dumps(data)
        print(f"Creating Current Rule {rulename}.........")
        put_response = requests.patch(url=url, data = data_payload, headers = finalHeader)
        put_response
        if put_response.status_code !=200:
          print ("Error Occured, One of the object doesn't exist, Check the response below", put_response.status_code)
          print (put_response.text)
        else:
            print("Rule created/Updated successfully" , put_response.status_code)
            print (put_response.text)


if __name__ == '__main__':
    finalHeader=login()
    baseurl = sddc_baseurl(finalHeader)
    main()
