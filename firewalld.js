'use strict';
const zoneFields=["target","icmp-block-inversion","interfaces","sources","services","ports","protocols","masquerade","forward-ports","source-ports","icmp-blocks","rich rules"];
const ipsetFields=["type","options","entries"];
const serviceFields=["ports","protocols","source-ports","modules","destination"];

function parseZoneBlock(block){
  let zone={};
  let arrLines=block.split("\n");
  let name=arrLines[0];
  let active=false;
 
  if(name.indexOf("(active)")!=-1){
    active=true;
    name=name.replace(" (active)","")
  }
  zone.name=name;
  zone.active=active;
  
  let i=0;
  for(i=0;i<arrLines.length;i++){
    let line=arrLines[i];
    let j=0;
    for(j=0;j<zoneFields.length;j++){
      let field=zoneFields[j];
      if(line.trim().indexOf(field+":")==0&&field!="rich rules"){
        zone[field]=line.trim().substr(field.length+1).trim();
        break;
      }
    }
  }
  return zone;
}

function parseIPset(ipset){
  let ret={};
  let arrLines=ipset.split("\n");
  let name=arrLines[0];
  ret.name=name;
  let i=0;
  for(i=0;i<arrLines.length;i++){
    let line=arrLines[i];
    if(line.trim().indexOf("type:")==0){
      ret.type=line.trim().substr("type:".length+1);
    }
    else if(line.trim().indexOf("options:")==0){
      ret.options=line.trim().substr("options:".length+1);
    }
    else if(line.trim().indexOf("entries:")==0){
      let tmp=line.trim().substr("entries:".length+1);
      if(tmp.length>0)
        ret.entries=tmp.split(" ");
      else
        ret.entries=[];
    }
  }
  return ret;
}

function parseService(block){
  let res={};
  let arrLines=block.split("\n");
  let name=arrLines[0];
  let active=false;
 
  res.name=name;
  
  let i=0;
  for(i=0;i<arrLines.length;i++){
    let line=arrLines[i];
    let j=0;
    for(j=0;j<serviceFields.length;j++){
      let field=serviceFields[j];
      if(line.trim().indexOf(field+":")==0){
        res[field]=line.trim().substr(field.length+1).trim();
        break;
      }
    }
  }
  return res;
}
module.exports = class JSFirewalld {
  /*zone related functions*/
  //get version
  getVersion(){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      let cmd='firewall-cmd --version';
      exec(cmd, (err, stdout, stderr) => {
        let result=[];
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve(stdout);
      });
    });
  }
  //zone related functions
  //list all zones
  listZones(isPermanent=false){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      let cmd='firewall-cmd --list-all-zones'+(isPermanent?" --permanent":"");
      exec(cmd, (err, stdout, stderr) => {
        let result=[];
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        let arrBlocks=stdout.split("\n\n");
        let i=0;
        for(i=0;i<arrBlocks.length-1;i++){
          let block=arrBlocks[i];
          let zone=parseZoneBlock(block);
          if(!zone){
            reject("failed to parse zone:"+block);
            return;
          }
          let cmd='firewall-cmd --zone='+zone.name+' --get-description'+' --permanent';
          exec(cmd, (err, stdout, stderr) => {
            if (err) {
              reject(err);
              return;
            }
            if(stderr&&stderr.length){
              reject(stderr);
              return;
            }
            zone.description=stdout;
            let cmd='firewall-cmd --zone='+zone.name+' --get-short'+' --permanent';
            exec(cmd, (err, stdout, stderr) => {
              if (err) {
                reject(err);
                return;
              }
              if(stderr&&stderr.length){
                reject(stderr);
                return;
              }
              zone.shortDesc=stdout;
              result.push(zone);
              if(result.length==arrBlocks.length-1)
                resolve(result);
            });
          });
        }
        
      });
    });
  }
  //create new zone
  addZone(zone){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --new-zone='+zone.name+" --permanent";
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        //set description
        let cmd='firewall-cmd --zone='+zone.name+' --set-description=\"'+zone.description+"\" --permanent";
        exec(cmd, (err, stdout, stderr) => {
          if (err) {
            reject(err);
            return;
          }
          if(stderr&&stderr.length){
            reject(stderr);
            return;
          }
          //set short description
          let cmd='firewall-cmd --zone='+zone.name+' --set-short=\"'+zone.shortDesc+"\" --permanent";
          exec(cmd, (err, stdout, stderr) => {
            if (err) {
              reject(err);
              return;
            }
            if(stderr&&stderr.length){
              reject(stderr);
              return;
            }
            let cmd='firewall-cmd --zone='+zone.name+' --set-target=\"'+zone.target+"\" --permanent";
            exec(cmd, (err, stdout, stderr) => {
              if (err) {
                reject(err);
                return;
              }
              if(stderr&&stderr.length){
                reject(stderr);
                return;
              }
              resolve();
            });
          });
        });
      });
    });
  }
  //remove zone
  removeZone(zone){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      exec('firewall-cmd --delete-zone='+ zone+ ' --permanent', (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //get certain zone
  queryZone(zone, isPermanent=false){
    const { exec } = require('child_process');
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --info-zone='+zone+ (isPermanent?' --permanent':'');
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        let result=parseZoneBlock(stdout);
        //todo description short description
        resolve(result);
      });
    });
  }
  /*ipset related functions*/
  //get ipset types
  getIPSetTypes(){
    const { exec } = require('child_process');
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --get-ipset-types';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        let result=stdout.split(' ');
        resolve(result);
      });
    });
    
  }
  //return array of IPset names
  listIPSetNames(isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --get-ipsets'+(isPermanent?" --permanent":"");
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve(stdout.trim().split(''));
      });
    });
  }
  addIPSet(name,type,family='inet',options=''){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      thisObj.getIPSetTypes()
      .then((setTypes)=>{
        if(setTypes.indexOf(type)==-1){
          reject('type:'+type+' not supported');
        }
        let cmd='firewall-cmd --new-ipset='+name+' --type='+type+' --family='+family;
        if(options!='')
          cmd+=' --option='+options;
        cmd+=' --permanent';
        exec(cmd, (err, stdout, stderr) => {
          if (err) {
            reject(err);
            return;
          }
          if(stderr&&stderr.length){
            reject(stderr);
            return;
          }
          resolve();
        });
      })
      .catch((e)=>{reject(e);});  
    });
  }
  removeIPSet(ipset){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --delete-ipset='+ipset;
      cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //add entry to ipset
  addIPSetEntry(ipset,entry,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --ipset='+ipset+' --add-entry='+entry;
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //remove entry from ipset
  removeIPSetEntry(ipset,entry,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --ipset='+ipset+' --remove-entry='+entry+(isPermanent?' --permanent':'');
      
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //check if entry exists
  IPsetEntryExists(ipset,entry,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --ipset='+ipset+' --query-entry='+entry;
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if(stdout.indexOf('yes')==0||stdout.indexOf('no')==0){
          resolve(stdout.indexOf('yes')==0);
          return;
        }
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
        
      });
    });
  }
  //get details of an ipset
  queryIPSet(ipset,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --info-ipset='+ipset;
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if(stderr&&stderr.length){
          if(stderr.indexOf('INVALID_IPSET')!=-1)
            resolve(null)
          else
            reject(stderr);
          return;
        }
        if (err) {
          reject(err);
          return;
        }
        
        let result=parseIPset(stdout);
        resolve(result);
      });
    });
  }
  //add entries by file 
  addIPSetByFile(ipset,filepath,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --ipset='+ipset+' --add-entries-from-file='+filepath;
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //remove entries by file 
  removeIPSetByFile(ipset,filepath,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --ipset='+ipset+' --remove-entries-from-file='+filepath;
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  
  /*source related functions*/
  //add source to zone
  addZoneSource(zone,source,isPermanent){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --zone='+zone+' --add-source='+source+(isPermanent?'  --permanent':'');
      
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //remove source from zone
  removeZoneSource(zone,source,isPermanent=false){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --zone='+zone+' --remove-source='+source+(isPermanent?'  --permanent':'');
     
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //get all source from zone
  listZoneSource(zone,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --zone='+zone+' --list-sources';
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
        let arr=stdout.trim().split(" ");
        
        resolve(arr);
      });
    });
  }
  //check if certain source exists in zone
  sourceExists(zone,source,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --zone='+zone+' --query-source='+source;
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if(stdout.indexOf('yes')==0||stdout.indexOf('no')==0){
          resolve(stdout.indexOf('yes')==0);
          return;
        }
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
      });
    });
  }
  
  /*rich rule related functions*/
  //add rich rule
  addRichRule(zone,rule,isPermanent){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --zone='+zone+' --add-rich-rule=\''+rule+'\''+(isPermanent?'  --permanent':'');
      
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //remove rich rule
  removeRichRule(zone,rule,isPermanent){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --zone='+zone+' --remove-rich-rule=\''+rule+'\''+(isPermanent?'  --permanent':'');
      
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //list all rich rules
  listRichRules(zone,isPermanent){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --zone='+zone+' --list-rich-rules';
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
        if(stdout=="\n")
          resolve([]);
        else{
          let arr=stdout.trim().split("\n");
          resolve(arr);
        }
      });
    });
  }
  //query one rich rule
  richRuleExists(zone,rule,isPermanent){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --zone='+zone+' --query-rich-rule=\''+rule+'\'';
      if(isPermanent)
        cmd+=' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if(stdout.indexOf('yes')==0||stdout.indexOf('no')==0){
          resolve(stdout.indexOf('yes')==0);
          return;
        }
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
        
      });
    });
  }
  
  /*service related functions*/
  /*query service*/
  queryService(service,isPermanent=false){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --info-service='+service+(isPermanent?" --permanent":"");
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          resolve(null);
          return;
        }
        if(stderr&&stderr.length){
          resolve(null);
          return;
        }
        let res=parseService(stdout);
        resolve(res);
      });
    });
  }
  
  //create a service
  createService(service){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --new-service='+service+'  --permanent';
      
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  
  //remove a service
  removeService(service){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --delete-service='+service+'  --permanent';
      
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //set service description
  setServiceDescription(service,description){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --set-description=\"'+description+'\"  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }  
  //get service description
  getServiceDescription(service){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --get-description  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve(stdout.trim());
      });
    });
  }
  //add port to service
  addServicePort(service,port){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --add-port='+port+'  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //remove service port
  removeServicePort(service,port){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --remove-port='+port+'  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //check if service port exists
  servicePortExists(service,port){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --service='+service+' --query-port='+port+' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if(stdout.indexOf('yes')==0||stdout.indexOf('no')==0){
          resolve(stdout.indexOf('yes')==0);
          return;
        }
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
      });
    });
  }
  //list all service ports
  listServicePorts(service){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --service='+service+' --get-ports --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
        if(stdout=="\n")
          resolve([]);
        else{
          let arr=stdout.trim().split(" ");
          resolve(arr);
        }
      });
    });
  }

  //add protocol to service
  addServiceProtocol(service,protocol){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --add-protocol='+protocol+'  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //remove protocol port
  removeServiceProtocol(service,protocol){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --remove-protocol='+protocol+'  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //check if service protocol exists
  serviceProtocolExists(service,protocol){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --service='+service+' --query-protocol='+protocol+' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if(stdout.indexOf('yes')==0||stdout.indexOf('no')==0){
          resolve(stdout.indexOf('yes')==0);
          return;
        }
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
      });
    });
  }
  //list all service protocols
  listServiceProtocols(service){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --service='+service+' --get-protocols --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
        if(stdout=="\n")
          resolve([]);
        else{
          let arr=stdout.trim().split(" ");
          resolve(arr);
        }
      });
    });
  }

  //add source port to service
  addServiceSourcePort(service,port){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --add-source-port='+port+'  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //remove source service port
  removeServiceSourcePort(service,port){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --remove-source-port='+port+'  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //check if service source port exists
  serviceSourcePortExists(service,port){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --service='+service+' --query-source-port='+port+' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if(stdout.indexOf('yes')==0||stdout.indexOf('no')==0){
          resolve(stdout.indexOf('yes')==0);
          return;
        }
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
      });
    });
  }
  //list all service source ports
  listServiceSourcePorts(service){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --service='+service+' --get-source-ports --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
        if(stdout=="\n")
          resolve([]);
        else{
          let arr=stdout.trim().split(" ");
          resolve(arr);
        }
      });
    });
  }

  //add destination to service
  addServiceDestination(service,destination){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --set-destination='+destination+'  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //remove service destination
  removeServiceDestination(service,destination){
    return new Promise(function(resolve, reject) {
      const { exec } = require('child_process');
      
      let cmd='';
      cmd='firewall-cmd --service='+service+' --remove-destination='+destination+'  --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          reject(stderr);
          return;
        }
        resolve();
      });
    });
  }
  //check if service destination exists
  serviceDestinationExists(service,destination){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --service='+service+' --query-destination='+destination+' --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if(stdout.indexOf('yes')==0||stdout.indexOf('no')==0){
          resolve(stdout.indexOf('yes')==0);
          return;
        }
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
      });
    });
  }
  //list all service source destinations
  listServiceDestinations(service){
    const { exec } = require('child_process');
    let thisObj=this;
    return new Promise(function(resolve, reject) {
      let cmd='firewall-cmd --service='+service+' --get-destinations --permanent';
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        if(stderr&&stderr.length){
          resolve(false);
          return;
        }
        if(stdout=="\n")
          resolve([]);
        else{
          let arr=stdout.trim().split(" ");
          resolve(arr);
        }
      });
    });
  }

}