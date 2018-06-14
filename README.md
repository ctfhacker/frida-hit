## Frida Hit Tracer

Function level hit tracer leveraging HexRays to display known types during a trace

## Manual compilation

### Install Rust

## Sample output

```
var base = parseInt(Module.findBaseAddress('samplemodule'));

try {
Interceptor.attach(ptr(base+0x1000), {
    onEnter: function(args) {
        //
        console.log(' '.repeat(this.depth*2) + '| + sub_401000(' + '' + ')');
    },

    onLeave: function(retVal) {
        console.log(' '.repeat(this.depth*2) + '| - sub_401000(' + '' + ') => (int ' + retVal + ')');
    }
});
} catch (err) {
    console.log(err + ' ERROR while attaching to sub_401000');
}


try {
Interceptor.attach(ptr(base+0x1050), {
    onEnter: function(args) {
        //
        console.log(' '.repeat(this.depth*2) + '| + sub_401050(' + '' + ')');
    },

    onLeave: function(retVal) {
        console.log(' '.repeat(this.depth*2) + '| - sub_401050(' + '' + ') => (int ' + retVal + ')');
    }
});
} catch (err) {
    console.log(err + ' ERROR while attaching to sub_401050');
}
```
