/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */

package com.github.katjahahn.jwscan.cli

import java.io.FileNotFoundException
import java.io.EOFException
import com.github.katjahahn.tools.sigscanner.Jar2ExeScanner
import java.io.File

/**
 * A scanner for Wrappers of Jar to Exe converters. This is the CLI frontend for 
 * the Jar2ExeScanner tool in PortEx (see:  https://github.com/katjahahn/PortEx)
 * It finds indicators about the tools used to wrap the jar into an EXE file, 
 * finds possible locations of the embedded jar file and may assist in dumping it.
 *
 * @author Katja Hahn
 */
object JWScanner {

  private val version = """version: 0.2.1
    |author: Katja Hahn
    |last update: 27.Oct 2014""".stripMargin

  private val title = "JWScan 0.2.1 -- by Katja Hahn"

  private val usage = """Usage: java -jar jwscan.jar [-d <hexoffset>] <PEfile>
    """.stripMargin

  private type OptionMap = scala.collection.mutable.Map[Symbol, String]

  def main(args: Array[String]): Unit = {
    invokeCLI(args)
  }

  private def invokeCLI(args: Array[String]): Unit = {
    val options = nextOption(scala.collection.mutable.Map(), args.toList)
    println(title + "\n")
    if (args.length == 0 || !options.contains('inputfile)) {
      println(usage)
    } else {
      try {
        println("scanning file ...\n")
        var file = new File(options('inputfile))
        println("file name: " + file + "\n")

        if (options.contains('version)) {
          println(version)
        }

        val scanner = new Jar2ExeScanner(file)
        println(scanner.createReport())

        if (options.contains('dump)) {
          dumpFile(options, scanner)
        }
      } catch {
        case e: FileNotFoundException => System.err.println(e.getMessage())
        case e: EOFException => System.err.println("given file is no PE file")
      }
    }
  }

  private def nextOption(map: OptionMap, list: List[String]): OptionMap = {
    list match {
      case Nil => map
      case "-d" :: value :: tail =>
        nextOption(map += ('dump -> value), tail)
      case "-v" :: tail =>
        nextOption(map += ('version -> ""), tail)
      case value :: Nil => nextOption(map += ('inputfile -> value), list.tail)
      case option :: tail =>
        println("Unknown option " + option + "\n" + usage)
        sys.exit(1)
    }
  }

  private def dumpFile(options: OptionMap, scanner: Jar2ExeScanner): Unit = {
    try {
      var dumped = new File("dumped.out")
      var hexoffset = options('dump)
      if (hexoffset.startsWith("0x")) {
        hexoffset = hexoffset.drop(2)
      }
      val addr = Integer.valueOf(hexoffset, 16)
      scanner.dumpAt(addr.toInt, dumped)
      println("successfully dumped from offset 0x" + hexoffset + " to " + dumped)
    } catch {
      case e: NumberFormatException => System.err.println("no valid offset")
    }
  }

}