'use strict';
const assert = require('assert');
function sleep(timeout){
  return new Promise(function(resolve, reject) {
    setTimeout(()=>{
      resolve();
    }, 1000);
  });
}
describe('JSFirewalld', function() {
  const JSFirewalld=require("../firewalld");
  const fd=new JSFirewalld();
  describe('#getVersion()', function() {
    it('should return version number as non-empty string', function(done) {
      fd.getVersion().then((version)=>{
        assert(version.length>0);
        done();
      })
    });
  });
  
  describe('#zone', function() {
    it('create/query/delete zone', async function() {
      this.timeout(10000);
      await fd.addZone({name:"testzone",description:"A test zone",shortDesc:"a_test_zone",target:"%%REJECT%%"});
      await sleep(100);
      let zone= await fd.queryZone('testzone',true);
      assert.equal(zone.name, 'testzone');
      await fd.removeZone("testzone");
    });
    
    it('list zones', async function() {
      this.timeout(20000);
      let zones= await fd.listZones();
      assert.equal(zones.length>0, true);
      let foundPublic=false;
      let foundInternal=false;
      let i=0;
      for(i=0;i<zones.length;i++){
        if(zones[i].name=='public'){
          foundPublic=true;
        }
        else if(zones[i].name=='internal'){
          foundInternal=true;
        }
      }
    });
    
    it('add/remove source to zone', async function() {
      this.timeout(10000);
      await fd.addZone({name:"testzone",description:"A test zone",shortDesc:"a_test_zone",target:"%%REJECT%%"});
      await sleep(100);
      await fd.addZoneSource("testzone","192.168.0.1/24",true);
      await sleep(100);
      let exists=await fd.sourceExists("testzone","192.168.0.1/24",true);
      assert.equal(exists, true);
      await fd.removeZoneSource("testzone","192.168.0.1/24",true);
      await sleep(100);
      exists=await fd.sourceExists("testzone","192.168.0.1/24",true);
      assert.equal(exists, false);
      await fd.removeZone("testzone");
    });
    
    it('list sources to zone', async function() {
      this.timeout(10000);
      await fd.addZone({name:"testzone",description:"A test zone",shortDesc:"a_test_zone",target:"%%REJECT%%"});
      await sleep(100);
      await fd.addZoneSource("testzone","192.168.0.1/24",true);
      await sleep(100);
      await fd.addZoneSource("testzone","192.168.1.1/24",true);
      await sleep(100);
      let arr=await fd.listZoneSource("testzone",true);
      assert.equal(arr[0], "192.168.0.1/24");
      assert.equal(arr[1], "192.168.1.1/24");
      await fd.removeZone("testzone");
    });
  });
  
  describe('#ipset', function() {
    it('create/query/delete ipset', async function() {
      this.timeout(10000);
      await fd.addIPSet('testipset','hash:ip','inet');
      await sleep(100);
      let ipset=await fd.queryIPSet('testipset',true);
      assert.equal(ipset.name, 'testipset');
      ipset=await fd.removeIPSet('testipset');
      assert.equal(ipset==null, true);
      
    });
    
    it('add/remove ipset entry', async function() {
      this.timeout(10000);
      await fd.addIPSet('testipset','hash:ip','inet');
      await sleep(100);
      await fd.addIPSetEntry('testipset','111.111.111.111',true);
      await sleep(100);
      let exists=await fd.IPsetEntryExists('testipset','111.111.111.111',true);
      assert.equal(exists, true);
      await fd.removeIPSetEntry('testipset','111.111.111.111',true);
      await sleep(100);
      exists=await fd.IPsetEntryExists('testipset','111.111.111.111',true);
      assert.equal(exists, false);
      await fd.removeIPSet('testipset');
      await sleep(100);
      let ipset=await fd.queryIPSet('testipset',true);
      assert.equal(ipset==null, true);
    });
    
     it('add/remove ipset entries by file', async function() {
        this.timeout(10000);
        await fd.addIPSet('testipset','hash:ip','inet');
        await sleep(100);
        await fd.addIPSetByFile('testipset',__dirname + '/templist.txt',true);
        await sleep(100);
        let exists=await fd.IPsetEntryExists('testipset','123.123.123.120',true);
        assert.equal(exists, true);
        await fd.removeIPSetByFile('testipset',__dirname +'/templist.txt',true);
        await sleep(100);
        exists=await fd.IPsetEntryExists('testipset','123.123.123.120',true);
        assert.equal(exists, false);
        await fd.removeIPSet('testipset');
        await sleep(100);
        let ipset=await fd.queryIPSet('testipset',true);
        assert.equal(ipset==null, true);
     });
  });
  
  describe('#rich rule', function() {
    it('create/query/delete rich rule', async function() {
      this.timeout(10000);
      await fd.addZone({name:"testzone",description:"A test zone",shortDesc:"a_test_zone",target:"%%REJECT%%"});
      await sleep(100);
      await fd.addRichRule('testzone','rule family="ipv4" source address="192.168.0.0/24" log prefix="local" level="info" accept',true);
      await sleep(100);
      let exists=await fd.richRuleExists("testzone",'rule family="ipv4" source address="192.168.0.0/24" log prefix="local" level="info" accept',true);
      assert.equal(exists, true);
      await fd.removeRichRule('testzone','rule family="ipv4" source address="192.168.0.0/24" log prefix="local" level="info" accept',true);
      exists=await fd.richRuleExists("testzone",'rule family="ipv4" source address="192.168.0.0/24" log prefix="local" level="info" accept',true);
      assert.equal(exists, false);
      await fd.removeZone("testzone");
    });
    
    it('list rich rules', async function() {
      this.timeout(20000);
      await fd.addZone({name:"testzone",description:"A test zone",shortDesc:"a_test_zone",target:"%%REJECT%%"});
      await sleep(100);
      await fd.addRichRule('testzone','rule family="ipv4" source address="192.168.0.0/24" log prefix="local" level="info" accept',true);
      await sleep(100);
      await fd.addRichRule('testzone','rule family="ipv4" source address="192.168.1.0/24" log prefix="local" level="info" accept',true);
      await sleep(100);
      let arr=await fd.listRichRules('testzone',true);
      assert.equal(arr.length, 2);
      assert.equal(arr[0], 'rule family="ipv4" source address="192.168.0.0/24" log prefix="local" level="info" accept');
      assert.equal(arr[1], 'rule family="ipv4" source address="192.168.1.0/24" log prefix="local" level="info" accept');
      await fd.removeRichRule('testzone','rule family="ipv4" source address="192.168.0.0/24" log prefix="local" level="info" accept',true);
      await fd.removeRichRule('testzone','rule family="ipv4" source address="192.168.1.0/24" log prefix="local" level="info" accept',true);
      await sleep(100);
      arr=await fd.listRichRules('testzone',true);
      assert.equal(arr.length, 0);
      await fd.removeZone("testzone");
    });
  });

  describe('#services', function() {
    it('create/query/delete services', async function() {
      this.timeout(10000);
      await fd.createService('testservice');
      await sleep(100);
      let service=await fd.queryService('testservice',true);
      assert.equal(service.name, 'testservice');
      await fd.removeService('testservice');
      service=await fd.queryService('testservice',true);
      assert.equal(service==null, true);
    });
    
    it('set/get services description', async function() {
      this.timeout(10000);
      await fd.createService('testservice');
      await sleep(100);
      await fd.setServiceDescription('testservice','test description');
      await sleep(100);
      let desc=await fd.getServiceDescription('testservice');
      assert.equal(desc, 'test description');
      await fd.removeService('testservice');
    });
    
    it('add/query/remove port', async function() {
      this.timeout(20000);
      await fd.createService('testservice');
      await sleep(100);
      await fd.addServicePort('testservice','88/tcp');
      await sleep(100);
      let exists=await fd.servicePortExists('testservice','88/tcp');
      assert.equal(exists, true);
      await fd.addServicePort('testservice','89/tcp');
      await sleep(100);
      exists=await fd.servicePortExists('testservice','89/tcp');
      assert.equal(exists, true);
      let arr=await fd.listServicePorts('testservice')
      assert.equal(arr.length, 2);
      assert.equal(arr[0], '88/tcp');
      assert.equal(arr[1], '89/tcp');
      await fd.removeService('testservice');
    });
    
    it('add/query/remove protocol', async function() {
      this.timeout(20000);
      await fd.createService('testservice');
      await sleep(100);
      await fd.addServiceProtocol('testservice','tcp');
      await sleep(100);
      let exists=await fd.serviceProtocolExists('testservice','tcp');
      assert.equal(exists, true);
      await fd.addServiceProtocol('testservice','udp');
      await sleep(100);
      exists=await fd.serviceProtocolExists('testservice','udp');
      assert.equal(exists, true);
      let arr=await fd.listServiceProtocols('testservice')
      assert.equal(arr.length, 2);
      assert.equal(arr[0], 'tcp');
      assert.equal(arr[1], 'udp');
      await fd.removeService('testservice');
    });
  
    it('add/query/remove source port', async function() {
      this.timeout(20000);
      await fd.createService('testservice');
      await sleep(100);
      await fd.addServiceSourcePort('testservice','88/tcp');
      await sleep(100);
      let exists=await fd.serviceSourcePortExists('testservice','88/tcp');
      assert.equal(exists, true);
      await fd.addServiceSourcePort('testservice','89/tcp');
      await sleep(100);
      exists=await fd.serviceSourcePortExists('testservice','89/tcp');
      assert.equal(exists, true);
      let arr=await fd.listServiceSourcePorts('testservice')
      assert.equal(arr.length, 2);
      assert.equal(arr[0], '88/tcp');
      assert.equal(arr[1], '89/tcp');
      await fd.removeService('testservice');
    });
  
    it('add/query/remove destination', async function() {
      this.timeout(20000);
      await fd.createService('testservice');
      await sleep(100);
      await fd.addServiceDestination('testservice','ipv4:192.168.1.0');
      await sleep(100);
      let exists=await fd.serviceDestinationExists('testservice','ipv4:192.168.1.0');
      assert.equal(exists, true);
      await fd.addServiceDestination('testservice','ipv4:192.168.2.0');
      await sleep(100);
      exists=await fd.serviceDestinationExists('testservice','ipv4:192.168.2.0');
      assert.equal(exists, true);
      let arr=await fd.listServiceDestinations('testservice')
      assert.equal(arr.length, 1);
      assert.equal(arr[0], 'ipv4:192.168.2.0');
      await fd.removeService('testservice');
    });
  });
});