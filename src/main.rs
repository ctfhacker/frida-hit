#![recursion_limit="128"]

#[macro_use]
extern crate nom;
extern crate clap;

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::error::Error;

use nom::{space};
use nom::IResult::{Done, self};

use clap::{App, Arg};

use std::i64;

#[derive(Debug)]
struct Function {
    return_type: String,
    calling_convention: Option<String>,
    name: String,
    arguments: Vec<Argument>
}

impl Function {
    pub fn frida_arguments(&self) -> String {
        let mut args = String::from("");
        for (i, arg) in self.arguments.iter().enumerate() {

            let mut arg_value = match arg.argument_type.as_str() {
                "const char *" => { format!("this.arg{} + \"->\" + Memory.readPointer(Memory.readUtf8String(this.arg{}))", i, i) },
                "LPCSTR"       => { format!("this.arg{} + \"->\" + Memory.readPointer(Memory.readUtf8String(this.arg{}))", i, i) },
                "char *"       => { format!("this.arg{} + \"->\" + Memory.readPointer(Memory.readUtf8String(this.arg{}))", i, i) },
                "int *"        => { format!("this.arg{} + \"->0x\" + Memory.readU32(this.arg{}).toString(16)", i, i) },
                "BYTE *"       => { format!("this.arg{} + \"->0x\" + Memory.readU8(this.arg{}).toString(16)", i, i) },
                "WORD *"       => { format!("this.arg{} + \"->0x\" + Memory.readU16(this.arg{}).toString(16)", i, i) },
                "DWORD *"      => { format!("this.arg{} + \"->0x\" + Memory.readU32(this.arg{}).toString(16)", i, i) },
                "QWORD *"      => { format!("this.arg{} + \"->0x\" + Memory.readU64(this.arg{}).toString(16)", i, i) },
                "_BYTE *"      => { format!("this.arg{} + \"->0x\" + Memory.readU8(this.arg{}).toString(16)", i, i) },
                "_WORD *"      => { format!("this.arg{} + \"->0x\" + Memory.readU16(this.arg{}).toString(16)", i, i) },
                "_DWORD *"     => { format!("this.arg{} + \"->0x\" + Memory.readU32(this.arg{}).toString(16)", i, i) },
                "_QWORD *"     => { format!("this.arg{} + \"->0x\" + Memory.readU64(this.arg{}).toString(16)", i, i) },
                _ => { format!("this.arg{}", i) }
            };
            
            if i > 0 {
                args = format!("{}', ({}) {}=' + {}", args, arg.argument_type, arg.name, arg_value);
            } else {
                args = format!("{}'({}) {}=' + {}", args, arg.argument_type, arg.name, arg_value);
            }

            if i != (self.arguments.len()-1) {
                args = format!("{} + ", args);
            }
        }
        args
    }
}

#[derive(Debug)]
struct Argument {
    argument_type: String,
    name: String,
}

fn get_function_signatures(filename: &str) -> Result<Vec<String>, io::Error> {
    let file = File::open(filename)?; 

    let mut data = String::new();
    let length = BufReader::new(file).read_to_string(&mut data)?;

    println!("size: {}", data.len());

    let functions = data.split("Function declarations")
                        .collect::<Vec<&str>>()[1]
                        .split("Data declarations")
                        .collect::<Vec<&str>>()[0]
                        .split("\r\n")
                        .map(String::from)
                        .collect::<Vec<String>>();
    for f in &functions {
        println!("{}", f);
    }

    Ok(functions)
}

fn main() {
    let matches = App::new("Hit Tracer powered by Frida")
                       .arg(Arg::with_name("INPUT_FILE")
                                .help("C File produced by Hex Rays for your current module")
                                .required(true))
                       .arg(Arg::with_name("BINARY_NAME")
                                 .help("Binary name of your module")
                                 .required(true))
                       .get_matches();


    let hex_rays_c = matches.value_of("INPUT_FILE").expect("Please provide input .c file");
    let binary_name = matches.value_of("BINARY_NAME").expect("Please provide binary name");

    let functions = get_function_signatures(hex_rays_c).ok().unwrap();

    let mut file_data: Vec<String> = vec!(String::from(format!("var base = parseInt(Module.findBaseAddress('{}'));", binary_name)));

    for f in functions {
        let res = parse_function(&f);
        if res.is_err() {
            println!("{}", f);
            println!("{:?}", res);
        }

        match res {
            Done(_, func) => {
                // println!("{:#?}", func);
                let frida_arguments = match func.frida_arguments().len() {
                    0 => String::from("''"),
                    _ => func.frida_arguments()
                };

                let self_args = match func.arguments.len() {
                    0 => String::from("//"),
                    x => {
                        let mut self_args: Vec<String> = vec!();
                        for i in 0..x {
                            self_args.push(format!("this.arg{i} = args[{i}];", i=i));
                        }
                        self_args.join("\n        ")
                    },
                };


                match i64::from_str_radix(&func.name.replace("sub_", ""), 16) {
                    Ok(num) =>  {
                        let curr_file_data = format!("
try {{
Interceptor.attach(ptr(base+{offset}), {{
    onEnter: function(args) {{
        {self_args}
        console.log(' '.repeat(this.depth*2) + '| + {func_name}(' + {arguments} + ')');
    }},

    onLeave: function(retVal) {{
        console.log(' '.repeat(this.depth*2) + '| - {func_name}(' + {arguments} + ') => ({return_type} ' + retVal + ')');
    }}
}});
}} catch (err) {{
    console.log(err + ' ERROR while attaching to {func_name}');
}}
", offset=format!("{:#x}", num-0x400000), func_name=func.name, arguments=frida_arguments, self_args=self_args, return_type=func.return_type);

                        file_data.push(curr_file_data);

                    },
                    _ => { 
                         println!("Check out: {}", func.name) ;
                        let curr_file_data = format!("
try {{
Interceptor.attach(ptr(parseInt(DebugSymbol.fromName('{func_name}')['address'])), {{
    onEnter: function(args) {{
        {self_args}
        console.log(' '.repeat(this.depth*2) + '| + {func_name}(' + {arguments} + ')');
    }},

    onLeave: function(retVal) {{
        console.log(' '.repeat(this.depth*2) + '| - {func_name}(' + {arguments} + ') => ({return_type} ' + retVal + ')');
    }}
}});
}} catch (err) {{
    console.log(err + ' ERROR while attaching to {func_name}');
}}
", func_name=func.name, arguments=frida_arguments, self_args=self_args, return_type=func.return_type);

                        file_data.push(curr_file_data);

                    }
                };
            },
            _ => {  }
        }
    }

    // let filepath = format!("__handlers__/{}/{}.js", binary_name, func.name.replace("sub_40", "sub_"));
    let filepath = "trace.js";
    let path = Path::new(&filepath);
    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", filepath, why.description()),
        Ok(file) => file,
    };

    match file.write_all(file_data.join("\n").as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", filepath, why.description()),
        Ok(_) => { 
            // println!("successfully wrote to {}", filepath),
        }
    }
}


named!(get_type<&str, &str>, 
        alt!(
            tag!("unsigned int *") | tag!("unsigned int") | 
            tag!("signed int *") | tag!("signed int") | 
            tag!("int *") | tag!("int") | 
            tag!("SOCKET *")  | tag!("SOCKET") | 
            tag!("DWORD *") | tag!("_DWORD *") | tag!("DWORD") | tag!("_DWORD") |
            tag!("__m128i *") | tag!("__m128i") |
            tag!("const char *") | tag!("char **") | tag!("char *") | tag!("char") |
            tag!("_BYTE *") | tag!("_BYTE") |  
            tag!("const void **") | tag!("const void *") | tag!("void **") | tag!("void *") | tag!("void") | 
            tag!("LPVOID *") | tag!("LPVOID") |
            tag!("HRESULT") | tag!("errno_t") | 
            tag!("u_short *") | tag!("u_short") |
            tag!("u_long *") | tag!("u_long") | 
            tag!("FILE *") | tag!("FILE") | 
            tag!("size_t") | tag!("bool") | tag!("double") |
            tag!("HANDLE") | tag!("LSTATUS") | 
            tag!("HMODULE *") | tag!("HMODULE") |
            tag!("BOOL") | tag!("LRESULT") |
            tag!("_QWORD *") | tag!("SIZE_T")  | tag!("_WORD *") | tag!("WORD *") | tag!("_WORD") | tag!("WORD") |
            tag!("FARPROC") | tag!("LPMALLOC *") | tag!("LPMALLOC") |
            tag!("const struct tm *") | tag!("const __time64_t *") | tag!("struct tm *") |
            tag!("wint_t") | tag!("const wchar_t *") | tag!("struct hostent *") |
            tag!("fd_set *") | tag!("const struct timeval") | tag!("LPWSADATA") | tag!("const struct sockaddr *") | tag!("struct sockaddr *") |
            tag!("HWND") | tag!("LPCSTR") | tag!("UINT") |
            tag!("const MSG *") | tag!("LPMSG") |
            tag!("std::_Locinfo *") | tag!("std::_Lockit *") | tag!("std::lcoale::_Locimp *") |
            tag!("LPCRITICAL_SECTION") | tag!("LPSECURITY_ATTRIBUTES") | tag!("LPTHREAD_START_ROUTINE") | 
            tag!("LPVOID") | tag!("LPDWORD") | tag!("LPWORD") | tag!("LPCSTR") | tag!("LPWSTR") |  tag!("LPBYTE") | 
            tag!("LPSTR") | tag!("LPCWSTR") | tag!("LPBOOL") | tag!("LPCVOID") | tag!("LPOVERLAPPED") |
            tag!("LPTOP_LEVEL_EXCEPTION_FILTER") | tag!("PSLIST_HEADER") | tag!("LPWIN32_FIND_DATAA") |
            tag!("LCID") | tag!("LCTYPE") | tag!("LPSTR") | tag!("LPSYSTEMTIME") | tag!("LPWIN32_FIND_DATAW") |
            tag!("const FILETIME *") | tag!("LPFILETIME") | tag!("va_list *") | tag!("va_list") |
            tag!("HKEY") | tag!("REGSAM") | tag!("PHKEY") | tag!("HLOCAL") | tag!("const struct std:::_Locimp *") | tag!("struct std::locale::_Locimp *") |
            tag!("const struct std::locale *") | tag!("const struct std::_Locinfo *")  |
            tag!("PSID") | tag!("LPHANDLER_FUNCTION") | tag!("SERVICE_STATUS_HANDLE") | tag!("struct _EXCEPTION_POINTERS") |
            tag!("__int16") | tag!("__int32") | tag!("__int64") | tag!("...") | tag!("HINSTANCE") |
            tag!("unsigned __int8 *") | tag!("unsigned __int8") | tag!("unsigned __int16 *") | tag!("unsigned __int16") |
            tag!("wchar_t *") | tag!("wchar_t")
        )
);

fn is_not_comma_or_paren(chr: char) -> bool {
    chr != ')' && chr != ','
}

named!(get_argument<&str, Argument>, do_parse!(
    arg_type: get_type >>
    opt!(space) >>
    name: opt!(take_while!( is_not_comma_or_paren )) >>
    alt!(tag!(", ") | tag!(")") ) >>
    (
        Argument {
            argument_type: String::from(arg_type),
            name: match name {
                Some(n) => String::from(n),
                _ => String::from("_") // Empty name field for Frida output
            }
        }
    )
));

named!(parse_function<&str, Function>, do_parse! (
        opt!(tag!("// ")) >>
        return_type: get_type >>
        opt!(space) >>
        calling_convention: opt!(alt!(tag!("__stdcall") | tag!("__cdecl static") | tag!("__cdecl") | tag!("__fastcall") | tag!("__thiscall") | tag!("__usercall"))) >>
        opt!(space) >>
        name: take_until!("(") >>
        tag!("(") >>
        args: many_till!( call!(get_argument), alt!(tag!(")") | tag!(";")) ) >>
        (
            Function {
                return_type: String::from(return_type),
                calling_convention: match calling_convention {
                    None => None,
                    Some(x) => Some(String::from(x))
                },
                name: String::from(name),
                arguments: args.0
            }
        )
    )
);
