# ${1:jsfirewalld}
TODO: A nodejs wrapper for firewall-cmd command
## Installation
npm i jsfirewalld /save

const JSFirewalld=require("jsfirewalld");
const fd=new JSFirewalld();
fd.getVersion().then((version)=>{
  console.log(version);
})

let zones= await fd.listZones();
console.log(JSON.stringify(zones));

//Please run with sudo as firewall-cmd need root privilege

TODO: Write usage instructions
## Contributing
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D
## History
TODO: Write history
## Credits
TODO: Write credits
## License
MIT
