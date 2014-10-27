import AssemblyKeys._ // put this at the top of the file

assemblySettings

jarName in assembly := "jwscan.jar"

test in assembly := {}

mainClass in assembly := Some("com.github.katjahahn.jwscan.cli.JWScan")
