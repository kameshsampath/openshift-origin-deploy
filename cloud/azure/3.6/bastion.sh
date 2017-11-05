#!/bin/bash

export MYARGS=$@
IFS=' ' read -r -a array <<< "$MYARGS"
export RESOURCEGROUP=$1
export WILDCARDZONE=$2
export AUSERNAME=$3
export PASSWORD=$4
export THEHOSTNAME=$5
export NODECOUNT=$6
export ROUTEREXTIP=$7
export SSHPRIVATEDATA=${8}
export SSHPUBLICDATA=${9}
export SSHPUBLICDATA2=${10}
export SSHPUBLICDATA3=${11}
export REGISTRYSTORAGENAME=${array[11]}
export REGISTRYKEY=${array[12]}
export LOCATION=${array[13]}
export SUBSCRIPTIONID=${array[14]}
export TENANTID=${array[15]}
export AADCLIENTID=${array[16]}
export AADCLIENTSECRET=${array[17]}
export METRICS=${array[18]}
export LOGGING=${array[19]}
export OPSLOGGING=${array[20]}
export GITURL=${array[21]}
export FULLDOMAIN=${THEHOSTNAME#*.*}
export WILDCARDFQDN=${WILDCARDZONE}.${FULLDOMAIN}
export WILDCARDIP=`dig +short ${WILDCARDFQDN}`
export WILDCARDNIP=${WILDCARDIP}.nip.io
export LOGGING_ES_INSTANCES="3"
export OPSLOGGING_ES_INSTANCES="3"
export METRICS_INSTANCES="1"
export LOGGING_ES_SIZE="10"
export OPSLOGGING_ES_SIZE="10"
export METRICS_CASSANDRASIZE="10"
export APIHOST=$RESOURCEGROUP.$FULLDOMAIN
echo "Show wildcard info"
echo $WILDCARDFQDN
echo $WILDCARDIP
echo $WILDCARDNIP
echo $GITURL

echo 'Show Registry Values'
echo $REGISTRYSTORAGENAME
echo $REGISTRYKEY
echo $LOCATION
echo $SUBSCRIPTIONID
echo $TENANTID
echo $AADCLIENTID
echo $AADCLIENTSECRET

domain=$(grep search /etc/resolv.conf | awk '{print $2}')

ps -ef | grep bastion.sh > cmdline.out

systemctl enable dnsmasq.service
systemctl start dnsmasq.service

echo "Resize Root FS"
rootdev=`findmnt --target / -o SOURCE -n`
rootdrivename=`lsblk -no pkname $rootdev`
rootdrive="/dev/"$rootdrivename
majorminor=`lsblk  $rootdev -o MAJ:MIN | tail -1`
part_number=${majorminor#*:}
yum install -y cloud-utils-growpart.noarch
growpart $rootdrive $part_number -u on
xfs_growfs $rootdev

mkdir -p /home/$AUSERNAME/.azuresettings
echo $REGISTRYSTORAGENAME > /home/$AUSERNAME/.azuresettings/registry_storage_name
echo $REGISTRYKEY > /home/$AUSERNAME/.azuresettings/registry_key
echo $LOCATION > /home/$AUSERNAME/.azuresettings/location
echo $SUBSCRIPTIONID > /home/$AUSERNAME/.azuresettings/subscription_id
echo $TENANTID > /home/$AUSERNAME/.azuresettings/tenant_id
echo $AADCLIENTID > /home/$AUSERNAME/.azuresettings/aad_client_id
echo $AADCLIENTSECRET > /home/$AUSERNAME/.azuresettings/aad_client_secret
echo $RESOURCEGROUP > /home/$AUSERNAME/.azuresettings/resource_group
chmod -R 600 /home/$AUSERNAME/.azuresettings/*
chown -R $AUSERNAME /home/$AUSERNAME/.azuresettings

mkdir -p /home/$AUSERNAME/.ssh
echo $SSHPUBLICDATA $SSHPUBLICDATA2 $SSHPUBLICDATA3 >  /home/$AUSERNAME/.ssh/id_rsa.pub
echo $SSHPRIVATEDATA | base64 --d > /home/$AUSERNAME/.ssh/id_rsa
chown $AUSERNAME /home/$AUSERNAME/.ssh/id_rsa.pub
chmod 600 /home/$AUSERNAME/.ssh/id_rsa.pub
chown $AUSERNAME /home/$AUSERNAME/.ssh/id_rsa
chmod 600 /home/$AUSERNAME/.ssh/id_rsa
cp /home/$AUSERNAME/.ssh/authorized_keys /root/.ssh/authorized_keys

mkdir -p /root/.azuresettings
echo $REGISTRYSTORAGENAME > /root/.azuresettings/registry_storage_name
echo $REGISTRYKEY > /root/.azuresettings/registry_key
echo $LOCATION > /root/.azuresettings/location
echo $SUBSCRIPTIONID > /root/.azuresettings/subscription_id
echo $TENANTID > /root/.azuresettings/tenant_id
echo $AADCLIENTID > /root/.azuresettings/aad_client_id
echo $AADCLIENTSECRET > /root/.azuresettings/aad_client_secret
echo $RESOURCEGROUP > /root/.azuresettings/resource_group
chmod -R 600 /root/.azuresettings/*
chown -R root /root/.azuresettings

mkdir -p /root/.ssh
echo $SSHPRIVATEDATA | base64 --d > /root/.ssh/id_rsa
echo $SSHPUBLICDATA $SSHPUBLICDATA2 $SSHPUBLICDATA3   >  /root/.ssh/id_rsa.pub
cp /home/$AUSERNAME/.ssh/authorized_keys /root/.ssh/authorized_keys
chown root /root/.ssh/id_rsa.pub
chmod 600 /root/.ssh/id_rsa.pub
chown root /root/.ssh/id_rsa
chmod 600 /root/.ssh/id_rsa
chown root /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

### TODO email notification setup 

sleep 30
echo "${RESOURCEGROUP} Bastion Host is starting software update" 
# Continue Setting Up Bastion
yum -y install epel-release centos-release-openshift-origin
yum -y install atomic-openshift-utils bash-completion bind-utils bridge-utils git iptables-services jq net-tools nodejs origin-clients qemu-img unzip wget
touch /root/.updateok

# Create azure.conf file

cat > /home/${AUSERNAME}/azure.conf <<EOF
{
   "tenantId": "$TENANTID",
   "subscriptionId": "$SUBSCRIPTIONID",
   "aadClientId": "$AADCLIENTID",
   "aadClientSecret": "$AADCLIENTSECRET",
   "aadTenantID": "$TENANTID",
   "resourceGroup": "$RESOURCEGROUP",
   "location": "$LOCATION",
}
EOF

cat > /home/${AUSERNAME}/vars.yml <<EOF
g_tenantId: $TENANTID
g_subscriptionId: $SUBSCRIPTIONID
g_aadClientId: $AADCLIENTID
g_aadClientSecret: $AADCLIENTSECRET
g_resourceGroup: $RESOURCEGROUP
g_location: $LOCATION
EOF

# Create Azure Cloud Provider configuration Playbook

cat > /home/${AUSERNAME}/azure-config.yml <<EOF
#!/usr/bin/ansible-playbook
- hosts: all
  gather_facts: no
  vars_files:
  - vars.yml
  become: yes
  vars:
    azure_conf_dir: /etc/azure
    azure_conf: "{{ azure_conf_dir }}/azure.conf"
  tasks:
  - name: make sure /etc/azure exists
    file:
      state: directory
      path: "{{ azure_conf_dir }}"

  - name: populate /etc/azure/azure.conf
    copy:
      dest: "{{ azure_conf }}"
      content: |
        {
          "aadClientID" : "{{ g_aadClientId }}",
          "aadClientSecret" : "{{ g_aadClientSecret }}",
          "subscriptionID" : "{{ g_subscriptionId }}",
          "tenantID" : "{{ g_tenantId }}",
          "resourceGroup": "{{ g_resourceGroup }}",
        }
EOF

cat <<EOF > /etc/ansible/hosts
[OSEv3:children]
masters
nodes
etcd
new_nodes

[OSEv3:vars]
osm_controller_args={'cloud-provider': ['azure'], 'cloud-config': ['/etc/azure/azure.conf']}
osm_api_server_args={'cloud-provider': ['azure'], 'cloud-config': ['/etc/azure/azure.conf']}
openshift_node_kubelet_args={'cloud-provider': ['azure'], 'cloud-config': ['/etc/azure/azure.conf'], 'enable-controller-attach-detach': ['true']}
debug_level=2
console_port=8443
docker_udev_workaround=True
openshift_node_debug_level="{{ node_debug_level | default(debug_level, true) }}"
openshift_master_debug_level="{{ master_debug_level | default(debug_level, true) }}"
openshift_master_access_token_max_seconds=2419200
openshift_hosted_router_replicas=1
openshift_hosted_registry_replicas=1
openshift_master_api_port="{{ console_port }}"
openshift_master_console_port="{{ console_port }}"
openshift_override_hostname_check=true
osm_use_cockpit=false
openshift_release=v3.6
openshift_cloudprovider_kind=azure
openshift_node_local_quota_per_fsgroup=512Mi
azure_resource_group=${RESOURCEGROUP}
openshift_install_examples=true
# Deployment type should be set to origin for origin deployment
deployment_type=origin
openshift_deployment_type=origin
openshift_master_identity_providers=[{'name': 'htpasswd_auth', 'login': 'true', 'challenge': 'true', 'kind': 'HTPasswdPasswordIdentityProvider', 'filename': '/etc/origin/master/htpasswd'}]
openshift_master_manage_htpasswd=false

# default selectors for router and registry services
openshift_router_selector='role=infra'
openshift_registry_selector='role=infra'

# Select default nodes for projects
osm_default_node_selector="role=app"
ansible_become=yes
ansible_ssh_user=${AUSERNAME}
remote_user=${AUSERNAME}

openshift_master_default_subdomain=${WILDCARDNIP}
#openshift_master_default_subdomain=${WILDCARDZONE}.${FULLDOMAIN}
# osm_default_subdomain=${WILDCARDZONE}.${FULLDOMAIN}
osm_default_subdomain=${WILDCARDNIP}
openshift_use_dnsmasq=true
openshift_public_hostname=${RESOURCEGROUP}.${FULLDOMAIN}

# Do not install metrics but post install
openshift_metrics_install_metrics=false
# openshift_metrics_cassandra_storage_type=pv
# openshift_metrics_cassandra_pvc_size="${METRICS_CASSANDRASIZE}G"
# openshift_metrics_cassandra_replicas="${METRICS_INSTANCES}"
# openshift_metrics_hawkular_nodeselector={"role":"infra"}
# openshift_metrics_cassandra_nodeselector={"role":"infra"}
# openshift_metrics_heapster_nodeselector={"role":"infra"}

# Do not install logging but post install
openshift_logging_install_logging=false
# openshift_logging_es_pv_selector={"usage":"elasticsearch"}
# openshift_logging_es_pvc_dynamic="false"
# openshift_logging_es_pvc_size="${LOGGING_ES_SIZE}G"
# openshift_logging_es_cluster_size=${LOGGING_ES_INSTANCES}
# openshift_logging_fluentd_nodeselector={"logging":"true"}
# openshift_logging_es_nodeselector={"role":"infra"}
# openshift_logging_kibana_nodeselector={"role":"infra"}
# openshift_logging_curator_nodeselector={"role":"infra"}

openshift_logging_use_ops=false
# openshift_logging_es_ops_pv_selector={"usage":"opselasticsearch"}
# openshift_logging_es_ops_pvc_dynamic="false"
# openshift_logging_es_ops_pvc_size="${OPSLOGGING_ES_SIZE}G"
# openshift_logging_es_ops_cluster_size=${OPSLOGGING_ES_INSTANCES}
# openshift_logging_es_ops_nodeselector={"role":"infra"}
# openshift_logging_kibana_ops_nodeselector={"role":"infra"}
# openshift_logging_curator_ops_nodeselector={"role":"infra"}

[masters]
master1 openshift_hostname=master1 openshift_node_labels="{'role': 'master'}"

[etcd]
master1

[new_nodes]

[nodes]
master1 openshift_hostname=master1 openshift_node_labels="{'role':'master','zone':'default','logging':'true'}" openshift_schedulable=false
infranode1 openshift_hostname=infranode1 openshift_node_labels="{'role': 'infra', 'zone': 'default','logging':'true'}"
EOF

# Loop to add Nodes
for (( c=01; c<$NODECOUNT+1; c++ ))
do
  pnum=$(printf "%02d" $c)
  echo "node${pnum} openshift_hostname=node${pnum} \
openshift_node_labels=\"{'role':'app','zone':'default','logging':'true'}\"" >> /etc/ansible/hosts
done

cat <<EOF >> /home/${AUSERNAME}/prereq.yml
---
- hosts: all
  vars:
    description: "Wait for nodes"
  tasks:
  - name: wait for .updateok
    wait_for: path=/root/.updateok
- hosts: all
  vars:
    description: "Install Prerequisite Packages"
  tasks:
  - name: Install EPEL Release Repo
    yum: name=epel-release state=latest
  - name: Install CentOS OpenShift Origin Release Repo
    yum: name=centos-release-openshift-origin
  - name: install the latest version of PyYAML
    yum: name=PyYAML state=latest
  - name: Update all hosts
    yum: name="*" state=latest
  - name: Install OpenShift Origin Clients
    yum: name=origin-clients state=latest
  - name: Install the docker
    yum: name=docker state=latest
  - name: Start Docker
    service:
      name: docker
      enabled: yes
      state: started
  - name: Wait for Things to Settle
    pause: minutes=2
EOF

cat <<EOF > /home/${AUSERNAME}/postinstall.yml
---
- hosts: masters
  vars:
    description: "auth users"
  tasks:
  - name: Create Master Directory
    file: path=/etc/origin/master state=directory
  - name: add initial user to Red Hat OpenShift Origin
    shell: htpasswd -c -b /etc/origin/master/htpasswd ${AUSERNAME} ${PASSWORD}

EOF

cat > /home/${AUSERNAME}/ssovars.yml <<EOF
---
  sso_username: ${AUSERNAME}
  sso_project: "sso"
  sso_password: ${PASSWORD}
  sso_domain:   ${WILDCARDNIP}
  hostname_https: "login.{{sso_domain}}"
  api_master:   ${APIHOST}
EOF

cat > /home/${AUSERNAME}/setup-sso.yml <<EOF
---
- hosts: masters[0]
  vars_files:
    - ssovars.yml
  vars:
    description: "SSO Setup"
    create_data:
        clientId: "openshift"
        name:     "OpenShift"
        description: "OpenShift Console Authentication"
        enabled: true
        protocol: "openid-connect"
        clientAuthenticatorType: "client-secret"
        directAccessGrantsEnabled: true
        redirectUris: ["https://{{api_master}}:8443/*"]
        webOrigins: []
        publicClient: false
        consentRequired: false
        frontchannelLogout: false
        standardFlowEnabled: true
  tasks:
  - debug:
      msg: "Domain: {{sso_domain}}"
  - set_fact: idm_dir="/home/{{sso_username}}/{{sso_project}}"
  - debug:
      msg: "Idm dir {{ idm_dir }}"
  - name: Install Java
    yum:
      name: java-1.8.0-openjdk
      state: latest
  - name: Cleanup old idm directory
    file:
      state: absent
      path: "{{idm_dir}}"
  - name: C eate new idm directory
    file:
      state: directory
      path: "{{idm_dir}}"
  - name: Delete service account
    command: oc delete service account "{{sso_project}}-service_account"
    ignore_errors: yes
    register: result
    failed_when:
      - "result.rc > 10"
  - name: Delete Secret
    command: oc delete secret "{{sso_project}}-app-secret"
    ignore_errors: yes
    register: result
    failed_when:
      - "result.rc > 10"
  - name: Delete Old Project
    command: oc delete project "{{sso_project}}"
    ignore_errors: yes
    register: result
    failed_when:
      - "result.rc > 10"
  - name: Pause for cleanup of old install
    pause:
      minutes: 2
  - set_fact: sso_projectid="{{sso_project}}"
  - set_fact: idm_xpassword="Xp-{{sso_password}}"
  - name: Create Openshift Project for SSO
    command: oc new-project "{{sso_project}}"
  - name: Create Service Account
    command: "oc create serviceaccount {{sso_project}}-service-account -n {{ sso_project }}"
  - name: Add admin role to user
    command: "oc adm policy add-role-to-user admin {{sso_username}}"
  - name: Add view to user
    command: "oc policy add-role-to-user view system:serviceaccount:${1}idm:{{sso_project}}-service-account"
  - name: Stage 1 - OpenSSL Request
    command: "openssl req -new  -passout pass:{{idm_xpassword}} -newkey rsa:4096 -x509 -keyout {{idm_dir}}/xpaas.key -out {{idm_dir}}/xpaas.crt -days 365 -subj /CN=xpaas-sso.ca"
  - name: Stage 2 - GENKEYPAIR
    command: "keytool  -genkeypair -deststorepass {{idm_xpassword}} -storepass {{idm_xpassword}} -keypass {{idm_xpassword}} -keyalg RSA -keysize 2048 -dname CN={{hostname_https}} -alias sso-https-key -keystore {{idm_dir}}/sso-https.jks"
  - name: Stage 3 - CERTREQ
    command: "keytool  -deststorepass {{idm_xpassword}} -storepass {{idm_xpassword}} -keypass {{idm_xpassword}} -certreq -keyalg rsa -alias sso-https-key -keystore {{idm_dir}}/sso-https.jks -file {{idm_dir}}/sso.csr"
  - name: Stage 4 - X509
    command: "openssl x509 -req -passin pass:{{idm_xpassword}} -CA {{idm_dir}}/xpaas.crt -CAkey {{idm_dir}}/xpaas.key -in {{idm_dir}}/sso.csr -out {{idm_dir}}/sso.crt -days 365 -CAcreateserial"
  - name: Stage 5 - IMPORT CRT
    command: "keytool  -noprompt -deststorepass {{idm_xpassword}} -import -file {{idm_dir}}/xpaas.crt  -storepass {{idm_xpassword}} -keypass {{idm_xpassword}} -alias xpaas.ca -keystore {{idm_dir}}/sso-https.jks"
  - name: Stage 6 - IMPORT SSO
    command: "keytool  -noprompt -deststorepass {{idm_xpassword}} -storepass {{idm_xpassword}} -keypass {{idm_xpassword}}  -import -file {{idm_dir}}/sso.crt -alias sso-https-key -keystore {{idm_dir}}/sso-https.jks"
  - name: Stage 7 - IMPORT XPAAS
    command: "keytool -noprompt -deststorepass {{idm_xpassword}} -storepass {{idm_xpassword}} -keypass {{idm_xpassword}}   -import -file {{idm_dir}}/xpaas.crt -alias xpaas.ca -keystore {{idm_dir}}/truststore.jks"
  - name: Stage 8 - GENSECKEY
    command: "keytool  -deststorepass {{idm_xpassword}} -storepass {{idm_xpassword}} -keypass {{idm_xpassword}} -genseckey -alias jgroups -storetype JCEKS -keystore {{idm_dir}}/jgroups.jceks"
  - name: Stage 9 - OCCREATE SECRET
    command: "oc create secret generic sso-app-secret --from-file={{idm_dir}}/jgroups.jceks --from-file={{idm_dir}}/sso-https.jks --from-file={{idm_dir}}/truststore.jks"
  - name: Stage 10 - OCCREATE SECRET ADD
    command: "oc secret add sa/{{sso_project}}-service-account secret/sso-app-secret"
  - name: Stage 11 - Create App Parameters
    blockinfile:
       path: "{{idm_dir}}/sso.params"
       create: yes
       block: |
         HOSTNAME_HTTP="nlogin.{{sso_domain}}"
         HOSTNAME_HTTPS="login.{{sso_domain}}"
         APPLICATION_NAME="{{sso_project}}"
         HTTPS_KEYSTORE="sso-https.jks"
         HTTPS_PASSWORD="{{idm_xpassword}}"
         HTTPS_SECRET="sso-app-secret"
         JGROUPS_ENCRYPT_KEYSTORE="jgroups.jceks"
         JGROUPS_ENCRYPT_PASSWORD="{{idm_xpassword}}"
         JGROUPS_ENCRYPT_SECRET="sso-app-secret"
         SERVICE_ACCOUNT_NAME={{sso_project}}-service-account
         SSO_REALM=cloud
         SSO_SERVICE_USERNAME="{{sso_username}}"
         SSO_SERVICE_PASSWORD="{{sso_password}}"
         SSO_ADMIN_USERNAME=admin
         SSO_ADMIN_PASSWORD="{{sso_password}}"
         SSO_TRUSTSTORE=truststore.jks
         SSO_TRUSTSTORE_PASSWORD="{{idm_xpassword}}"

  - name: Stage 10 - OCCREATE SECRET ADD
    command: oc new-app sso71-postgresql --param-file {{idm_dir}}/sso.params -l app=sso71-postgresql -l application=sso -l template=sso71-https
  - set_fact: sso_token_url="https://login.{{sso_domain}}/auth/realms/cloud/protocol/openid-connect/token"
  - name: Pause for app create
    pause:
      minutes: 4
  - name: Login to SSO and Get Token
    uri:
      url: "{{sso_token_url}}"
      method: POST
      body: "grant_type=password&client_id=admin-cli&username={{sso_username}}&password={{sso_password}}"
      return_content: yes
      status_code: 200
      validate_certs: no
    register: login
    until: login.status == 200
    retries: 90
    delay: 30
  - debug: var=login.json.access_token
  - name: Create SSO Client for Openshift
    uri:
      url: "https://login.{{sso_domain}}/auth/realms/cloud/clients-registrations/default"
      method: POST
      headers:
           "Authorization": "bearer {{login.json.access_token}}"
           "Content-Type": "application/json"
      body: "{{ create_data | to_json }}"
      return_content: yes
      status_code: 201
      validate_certs: no
    register: create
  - debug: var=create.json.secret
  - local_action: copy content={{create.json.secret}} dest=/tmp/ssosecret.var
  - fetch:
       src: "{{idm_dir}}/xpaas.crt"
       dest: "{{idm_dir}}/xpaas.crt"
       flat: yes
- hosts: masters
  vars_files:
    - ssovars.yml
  vars:
     ssosecret: "{{lookup('file', '/tmp/ssosecret.var')}}"
  tasks:
  - set_fact: idm_dir="/home/{{sso_username}}/{{sso_project}}"
  - name: Copy xpass.crt to masters
    copy:
      src:  "{{idm_dir}}/xpaas.crt"
      dest: /etc/origin/master/xpaas.crt
      owner: root
      mode: 0600
  - name: Setup SSO Config
    blockinfile:
      backup: yes
      dest: /etc/origin/master/master-config.yaml
      insertafter: HTPasswdPasswordIdentityProvider
      block: |1
         - name: sso
           challenge: false
           login: true
           mappingInfo: add
           provider:
             apiVersion: v1
             kind: OpenIDIdentityProvider
             clientID: openshift
             clientSecret: {{ssosecret}}
             ca: xpaas.crt
             urls:
               authorize: https://login.{{sso_domain}}/auth/realms/cloud/protocol/openid-connect/auth
               token: https://login.{{sso_domain}}/auth/realms/cloud/protocol/openid-connect/token
               userInfo: https://login.{{sso_domain}}/auth/realms/cloud/protocol/openid-connect/userinfo
             claims:
               id:
               - sub
               preferredUsername:
               - preferred_username
               name:
               - name
               email:
               - email

  - service:
      name: origin-master
      state: restarted
  - service:
      name: origin-node
      state: restarted
  - name: Pause for service restart
    pause:
      seconds: 10
  - name: Add our user as cluster admin
    command: oc adm policy add-cluster-role-to-user cluster-admin "{{sso_username}}"
  - debug:
      msg: "Completed"
EOF

cat > /home/${AUSERNAME}/add_host.sh <<EOF
#!/bin/bash
set -eo pipefail

usage(){
  echo "$0 [-t node|master|infranode] [-u username] [-p /path/to/publicsshkey] [-s vmsize] [-d extradisksize (in G)] [-d extradisksize] [-d...]"
  echo "  -t|--type           node"
  echo "                      If not specified: node"
  echo "  -u|--user           regular user to be created on the host"
  echo "                      If not specified: Current user"
  echo "  -p|--sshpub         path to the public ssh key to be injected in the host"
  echo "                      If not specified: ~/.ssh/id_rsa.pub"
  echo "  -s|--size           VM size"
  echo "                      If not specified:"
  echo "                        * Standard_DS12_v2 for nodes"
  echo "  -d|--disk           Extra disk size in GB (it can be repeated a few times)"
  echo "                      If not specified: 2x128GB"
  echo "Examples:"
  echo "    $0 -t infranode -d 200 -d 10"
  echo "    $0"
}

login_azure(){
  export TENANT=$(< ~/.azuresettings/tenant_id)
  export AAD_CLIENT_ID=$(< ~/.azuresettings/aad_client_id)
  export AAD_CLIENT_SECRET=$(< ~/.azuresettings/aad_client_secret)
  export RESOURCEGROUP=$(< ~/.azuresettings/resource_group)
  export LOCATION=$(< ~/.azuresettings/location)
  echo "Logging into Azure..."
  azure login \
    --service-principal \
    --tenant ${TENANT} \
    -u ${AAD_CLIENT_ID} \
    -p ${AAD_CLIENT_SECRET} >/dev/null
}

create_nic_azure(){
  echo "Creating the VM NIC..."
  azure network nic create \
    --resource-group ${RESOURCEGROUP} \
    --name ${VMNAME}nic \
    --location ${LOCATION} \
    --subnet-id  "/subscriptions/${SUBSCRIPTION}/resourceGroups/${RESOURCEGROUP}/providers/Microsoft.Network/virtualNetworks/${NET}/subnets/${SUBNET}" \
    --ip-config-name ${IPCONFIG} \
    --internal-dns-name-label ${VMNAME} \
    --tags "displayName=NetworkInterface" >/dev/null
}
create_vm_azure(){
  # VM itself
  echo "Creating the VM..."
  azure vm create \
    --resource-group ${RESOURCEGROUP} \
    --name ${VMNAME} \
    --location ${LOCATION} \
    --image-urn ${IMAGE} \
    --admin-username ${ADMIN} \
    --ssh-publickey-file ${SSHPUB} \
    --vm-size ${VMSIZE} \
    --storage-account-name ${SA} \
    --storage-account-container-name ${SACONTAINER} \
    --os-disk-vhd http://${SA}.blob.core.windows.net/${SACONTAINER}/${VMNAME}.vhd \
    --nic-name ${VMNAME}nic \
    --availset-name ${TYPE}availabilityset \
    --os-type Linux \
    --disable-boot-diagnostics \
    --tags "displayName=VirtualMachine" >/dev/null
}

create_disks_azure(){
  # Disks
  echo "Creating the VM disks..."
  for ((i=0; i<${#DISKS[@]}; i++))
  do
    azure vm disk attach-new \
      --resource-group ${RESOURCEGROUP} \
      --vm-name ${VMNAME} \
      --size-in-gb ${DISKS[i]} \
      --vhd-name ${VMNAME}_datadisk${i}.vhd \
      --storage-account-name ${SA} \
      --storage-account-container-name ${SACONTAINER} \
      --host-caching ${HOSTCACHING} >/dev/null
  done
}

create_host_azure(){
  create_nic_azure
  create_vm_azure
  create_disks_azure
}

create_nsg_azure()
{
  echo "Creating the NGS..."
  azure network nsg create \
    --resource-group ${RESOURCEGROUP} \
    --name ${VMNAME}nsg \
    --location ${LOCATION} \
    --tags "displayName=NetworkSecurityGroup" >/dev/null
}
attach_nsg_azure()
{
  echo "Attaching NGS rules to a NSG..."
  azure network nic set \
    --resource-group ${RESOURCEGROUP} \
    --name ${VMNAME}nic \
    --network-security-group-name ${VMNAME}nsg >/dev/null
}

create_node_azure()
{
  common_azure
  export SUBNET="nodeSubnet"
  export SA="sanod${RESOURCEGROUP}"
  create_host_azure
}

common_azure()
{
  echo "Getting the VM name..."
  export LASTVM=$(azure vm list ${RESOURCEGROUP} | awk "/${TYPE}/ { print \$3 }" | tail -n1)
  if [ $TYPE == 'node' ]
  then
    # Get last 2 numbers and add 1
    LASTNUMBER=$((10#${LASTVM: -2}+1))
    # Format properly XX
    NEXT=$(printf %02d $LASTNUMBER)
  else
    # Get last number
    NEXT=$((${LASTVM: -1}+1))
  fi
  export VMNAME="${TYPE}${NEXT}"
  export SUBSCRIPTION=$(azure account list --json | jq -r '.[0].id')
}

add_node_openshift(){
  echo "Adding the new node to the ansible inventory..."
  sudo sed -i "/\[new_nodes\]/a ${VMNAME} openshift_hostname=${VMNAME} openshift_node_labels=\"{'role':'${ROLE}','zone':'default','logging':'true'}\"" /etc/ansible/hosts
  echo "Preparing the host..."
  ansible new_nodes -m shell -a "curl -s ${GITURL}node.sh | bash -x" >/dev/null
  export ANSIBLE_HOST_KEY_CHECKING=False
  ansible-playbook -l new_nodes /home/${USER}/prereq.yml
  ansible-playbook -l new_nodes -e@vars.yml /home/${USER}/azure-config.yml
  # Scale up
  echo "Scaling up the node..."
  ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/byo/openshift-node/scaleup.yml
  echo "Adding the node to the ansible inventory..."
  sudo sed -i "/^${VMNAME}.*/d" /etc/ansible/hosts
  sudo sed -i "/\[nodes\]/a ${VMNAME} openshift_hostname=${VMNAME} openshift_node_labels=\"{'role':'${ROLE}','zone':'default','logging':'true'}\"" /etc/ansible/hosts
}

# Default values
export IPCONFIG="ipconfig1"
export HOSTCACHING="None"
export NET="openshiftVnet"
export IMAGE="CENTOS"
export SACONTAINER="openshiftvmachines"
export APIPORT="8443"
export HTTP="80"
export HTTPS="443"

# Default values that can be overwritten with flags
DEFTYPE="node"
DEFSSHPUB="/home/${USER}/.ssh/id_rsa.pub"
DEFVMSIZENODE="Standard_DS12_v2"
DEFVMSIZEINFRANODE="Standard_DS12_v2"
DEFVMSIZEMASTER="Standard_DS3_v2"
declare -a DEFDISKS=(128 128)

if [[ ( $@ == "--help") ||  $@ == "-h" ]]
then
  usage
  exit 0
fi

while [[ $# -gt 0 ]]; do
  opt="$1"
  shift;
  current_arg="$1"
  if [[ "$current_arg" =~ ^-{1,2}.* ]]; then
    echo "ERROR: You may have left an argument blank. Double check your command."
    usage; exit 1
  fi
  case "$opt" in
    "-t"|"--type")
      TYPE="${1,,}"
      shift
      ;;
    "-u"|"--user")
      ADMIN="$1"
      shift
      ;;
    "-p"|"--sshpub")
      SSHPUB="$1"
      shift
      ;;
    "-s"|"--size")
      VMSIZE="$1"
      shift
      ;;
    "-d"|"--disk")
      DISKS+=("$1")
      shift
      ;;
    *)
      echo "ERROR: Invalid option: \""$opt"\"" >&2
      usage
      exit 1
      ;;
  esac
done

export TYPE=${TYPE:-${DEFTYPE}}
export ADMIN=${ADMIN:-${USER}}
export SSHPUB=${SSHPUB:-${DEFSSHPUB}}
export DISKS=("${DISKS[@]:-${DEFDISKS[@]}}")

azure telemetry --disable 1>/dev/null
login_azure

case "$TYPE" in
  'node')
    # NODE
    export VMSIZE=${VMSIZE:-$DEFVMSIZENODE}
    export ROLE="app"
    echo "Creating a new node..."
    create_node_azure
    echo "Adding the node to Origin..."
    add_node_openshift
    ;;
esac

echo "Done"
EOF
chmod a+x /home/${AUSERNAME}/add_host.sh

npm install -g azure-cli
azure telemetry --disable
cat <<'EOF' > /home/${AUSERNAME}/create_azure_storage_container.sh
# $1 is the storage account to create container
mkdir -p ~/.azuresettings/$1
export TENANT=$(< ~/.azuresettings/tenant_id)
export AAD_CLIENT_ID=$(< ~/.azuresettings/aad_client_id)
export AAD_CLIENT_SECRET=$(< ~/.azuresettings/aad_client_secret)
export RESOURCEGROUP=$(< ~/.azuresettings/resource_group)
azure login --service-principal --tenant ${TENANT}  -u ${AAD_CLIENT_ID} -p ${AAD_CLIENT_SECRET}
azure storage account connectionstring show ${1} --resource-group ${RESOURCEGROUP}  > ~/.azuresettings/$1/connection.out
sed -n '/connectionstring:/{p}' < ~/.azuresettings/${1}/connection.out > ~/.azuresettings/${1}/dataline.out
export DATALINE=$(< ~/.azuresettings/${1}/dataline.out)
export AZURE_STORAGE_CONNECTION_STRING=${DATALINE:27}
azure storage container create ${2} > ~/.azuresettings/${1}/container.dat
EOF
chmod +x /home/${AUSERNAME}/create_azure_storage_container.sh

cat <<EOF > /home/${AUSERNAME}/scgeneric.yml
kind: StorageClass
apiVersion: storage.k8s.io/v1beta1
metadata:
  name: "generic"
  annotations:
    storageclass.beta.kubernetes.io/is-default-class: "true"
    volume.beta.kubernetes.io/storage-class: "generic"
    volume.beta.kubernetes.io/storage-provisioner: kubernetes.io/azure-disk
provisioner: kubernetes.io/azure-disk
parameters:
  storageAccount: sapv${RESOURCEGROUP}
EOF

cat <<EOF > /home/${AUSERNAME}/openshift-install.sh
export ANSIBLE_HOST_KEY_CHECKING=False
sleep 120
ansible all --module-name=ping > ansible-preinstall-ping.out || true
ansible-playbook  /home/${AUSERNAME}/prereq.yml
ansible-playbook  /home/${AUSERNAME}/azure-config.yml
echo "${RESOURCEGROUP} Bastion Host is starting ansible BYO"
ansible-playbook  /usr/share/ansible/openshift-ansible/playbooks/byo/config.yml < /dev/null

wget http://master1:8443/api > healtcheck.out

ansible all -b -m command -a "nmcli con modify eth0 ipv4.dns-search $(domainname -d)"
ansible all -b -m service -a "name=NetworkManager state=restarted"

ansible-playbook /home/${AUSERNAME}/postinstall.yml
cd /root
mkdir .kube
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${AUSERNAME}@master1:~/.kube/config /tmp/kube-config
cp /tmp/kube-config /root/.kube/config
mkdir /home/${AUSERNAME}/.kube
cp /tmp/kube-config /home/${AUSERNAME}/.kube/config
chown --recursive ${AUSERNAME} /home/${AUSERNAME}/.kube
rm -f /tmp/kube-config
echo "setup registry for azure"
oc env dc docker-registry -e REGISTRY_STORAGE=azure -e REGISTRY_STORAGE_AZURE_ACCOUNTNAME=$REGISTRYSTORAGENAME -e REGISTRY_STORAGE_AZURE_ACCOUNTKEY=$REGISTRYKEY -e REGISTRY_STORAGE_AZURE_CONTAINER=registry
oc patch dc registry-console -p '{"spec":{"template":{"spec":{"nodeSelector":{"role":"infra"}}}}}'
sleep 30
echo "Setup Azure PV"
/home/${AUSERNAME}/create_azure_storage_container.sh sapv${RESOURCEGROUP} "vhds"

echo "Setup Azure PV for metrics & logging"
/home/${AUSERNAME}/create_azure_storage_container.sh sapvlm${RESOURCEGROUP} "loggingmetricspv"

oc adm policy add-cluster-role-to-user cluster-admin ${AUSERNAME}
# Workaround for BZ1469358
ansible master1 -b -m fetch -a "src=/etc/origin/master/ca.serial.txt dest=/tmp/ca.serial.txt flat=true"
ansible masters -b -m copy -a "src=/tmp/ca.serial.txt dest=/etc/origin/master/ca.serial.txt mode=644 owner=root"
ansible-playbook /home/${AUSERNAME}/setup-sso.yml &> /home/${AUSERNAME}/setup-sso.out 
touch /root/.openshiftcomplete
touch /home/${AUSERNAME}/.openshiftcomplete
EOF

cat <<EOF > /home/${AUSERNAME}/openshift-postinstall.sh
export ANSIBLE_HOST_KEY_CHECKING=False

DEPLOYMETRICS=${METRICS,,}
DEPLOYLOGGING=${LOGGING,,}
DEPLOYOPSLOGGING=${OPSLOGGING,,}

while true
do
  [ -e /home/${AUSERNAME}/.openshiftcomplete ] && break || sleep 10
done

if [ \${DEPLOYMETRICS} == "true" ]
then
  echo "Deploying Metrics"
  /home/${AUSERNAME}/create_pv.sh sapvlm${RESOURCEGROUP} loggingmetricspv metricspv ${METRICS_INSTANCES} ${METRICS_CASSANDRASIZE}
  ansible-playbook -e "openshift_metrics_install_metrics=\${DEPLOYMETRICS}" /usr/share/ansible/openshift-ansible/playbooks/byo/openshift-cluster/openshift-metrics.yml
fi

if [ \${DEPLOYLOGGING} == "true" ] || [ \${DEPLOYOPSLOGGING} == "true" ]
then
  if [ \${DEPLOYLOGGING} == "true" ]
  then
    /home/${AUSERNAME}/create_pv.sh sapvlm${RESOURCEGROUP} loggingmetricspv loggingpv ${LOGGING_ES_INSTANCES} ${LOGGING_ES_SIZE}
    for ((i=0;i<${LOGGING_ES_INSTANCES};i++))
    do
      oc patch pv/loggingpv-\${i} -p '{"metadata":{"labels":{"usage":"elasticsearch"}}}'
    done
  fi

  if [ \${DEPLOYOPSLOGGING} == true ]
  then
    /home/${AUSERNAME}/create_pv.sh sapvlm${RESOURCEGROUP} loggingmetricspv loggingopspv ${OPSLOGGING_ES_INSTANCES} ${OPSLOGGING_ES_SIZE}
    for ((i=0;i<${OPSLOGGING_ES_INSTANCES};i++))
    do
      oc patch pv/loggingopspv-\${i} -p '{"metadata":{"labels":{"usage":"opselasticsearch"}}}'
    done
  fi
  ansible-playbook -e "openshift_logging_install_logging=\${DEPLOYLOGGING} openshift_logging_use_ops=\${DEPLOYOPSLOGGING}" /usr/share/ansible/openshift-ansible/playbooks/byo/openshift-cluster/openshift-logging.yml
fi

oc create -f /home/${AUSERNAME}/scgeneric.yml
EOF

cat <<'EOF' > /home/${AUSERNAME}/create_pv.sh
# $1 is the storage account to create container
# $2 is the container
# $3 is the blob
# $4 is the times
# $5 is the size in gigabytes

mkdir -p ~/.azuresettings/$1
export TENANT=$(< ~/.azuresettings/tenant_id)
export AAD_CLIENT_ID=$(< ~/.azuresettings/aad_client_id)
export AAD_CLIENT_SECRET=$(< ~/.azuresettings/aad_client_secret)
export RESOURCEGROUP=$(< ~/.azuresettings/resource_group)
azure login --service-principal --tenant ${TENANT}  -u ${AAD_CLIENT_ID} -p ${AAD_CLIENT_SECRET}
azure storage account connectionstring show ${1} --resource-group ${RESOURCEGROUP} > ~/.azuresettings/$1/connection.out
sed -n '/connectionstring:/{p}' < ~/.azuresettings/${1}/connection.out > ~/.azuresettings/${1}/dataline.out
export DATALINE=$(< ~/.azuresettings/${1}/dataline.out)
export AZURE_STORAGE_CONNECTION_STRING=${DATALINE:27}

qemu-img create -f raw /tmp/image.raw ${5}G
mkfs.xfs /tmp/image.raw
qemu-img convert -f raw -o subformat=fixed -O vpc /tmp/image.raw /tmp/image.vhd
rm -f /tmp/image.raw

TIMES=$(expr ${4} - 1)

for ((i=0;i<=TIMES;i++))
do
  azure storage blob upload /tmp/image.vhd ${2} $3-${i}.vhd
  echo "https://${1}.blob.core.windows.net/${2}/$3-${i}.vhd"

  cat<<OEF | oc create -f -
apiVersion: "v1"
kind: "PersistentVolume"
metadata:
  name: "${3}-${i}"
spec:
  capacity:
    storage: "${5}Gi"
  accessModes:
    - "ReadWriteOnce"
  persistentVolumeReclaimPolicy: Delete
  azureDisk:
    diskName: "${3}-${i}"
    diskURI: "https://${1}.blob.core.windows.net/${2}/${3}-${i}.vhd"
    cachingMode: None
    fsType: xfs
    readOnly: false
OEF
done

rm -f /tmp/image.vhd
EOF

chmod +x /home/${AUSERNAME}/create_pv.sh

cat <<EOF > /home/${AUSERNAME}/.ansible.cfg
[defaults]
remote_tmp     = ~/.ansible/tmp
local_tmp      = ~/.ansible/tmp
host_key_checking = False
forks=30
gather_timeout=60
timeout=240
library = /usr/share/ansible:/usr/share/ansible/openshift-ansible/library
[ssh_connection]
control_path = ~/.ansible/cp/ssh%%h-%%p-%%r
ssh_args = -o ControlMaster=auto -o ControlPersist=600s -o ControlPath=~/.ansible/cp-%h-%p-%r
EOF
chown ${AUSERNAME} /home/${AUSERNAME}/.ansible.cfg

cat <<EOF > /root/.ansible.cfg
[defaults]
remote_tmp     = ~/.ansible/tmp
local_tmp      = ~/.ansible/tmp
host_key_checking = False
forks=30
gather_timeout=60
timeout=240
library = /usr/share/ansible:/usr/share/ansible/openshift-ansible/library
[ssh_connection]
control_path = ~/.ansible/cp/ssh%%h-%%p-%%r
ssh_args = -o ControlMaster=auto -o ControlPersist=600s -o ControlPath=~/.ansible/cp-%h-%p-%r
EOF


cd /home/${AUSERNAME}
chmod 755 /home/${AUSERNAME}/openshift-install.sh
echo "${RESOURCEGROUP} Bastion Host is starting OpenShift Install" || true
/home/${AUSERNAME}/openshift-install.sh &> /home/${AUSERNAME}/openshift-install.out &
chmod 755 /home/${AUSERNAME}/openshift-postinstall.sh
/home/${AUSERNAME}/openshift-postinstall.sh &> /home/${AUSERNAME}/openshift-postinstall.out &
exit 0
