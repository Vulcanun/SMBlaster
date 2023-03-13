using System;
using System.IO;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace SMBlaster
{
    public class RuleParser
    {
        public class Pinto
        {
            public List<Rule> Rules;
        }

        public class RuleFilter
        {
            public bool Filename { get; set; }
            public bool Path { get; set; }
            public bool Extension { get; set; }
            public bool Content { get; set; }
            public bool Writable { get; set; }
            public bool Readable { get; set; }
            public bool Deletable { get; set; }
            public bool DirectoryWritable { get; set; }
            public bool Seizable { get; set; }
        }

        public class Rule
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public List<string> Filename { get; set; }
            public List<string> Path { get; set; }
            public List<string> Extension { get; set; }
            public List<string> Content { get; set; }
            public bool? Writable { get; set; } = null;
            public bool? Readable { get; set; } = null;
            public bool? Deletable { get; set; } = null;
            public bool? DirectoryWritable { get; set; } = null;
            public bool? Seizable { get; set; } = null;
        }

        public Pinto parseRulesFile(string ruleFilePath)
        {
            string jsonRules = File.ReadAllText(ruleFilePath);
            return JsonConvert.DeserializeObject<Pinto>(jsonRules);
        }
    }
}

//{
//  "Name": "Sample Rule",
//	"Description": "This rule contains every possible field a rule could use. This is for demonstration purposes and the combination of the fields below might not make sense with one another.",
//	"Filename": [
//      "vnc.ini",
//		"ultravnc.ini",
//		"mypassword"
//	],
//	"Path": [
//      "Users\\\\Public",
//		"New Folder",
//		"\\.aws"
//	],
//	"Extension": [
//      "ini",
//		"txt",
//		"csv"
//	],
//	"Content": [
//      "senha",
//		"password",
//		"pwd"
//	],
//	"Writable": true,
//	"Readable": true,
//	"Deletable": true,
//	"DirectoryWritable": true,
//	"Seizable": true
//}