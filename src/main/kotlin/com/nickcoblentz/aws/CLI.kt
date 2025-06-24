package com.nickcoblentz.aws

import com.nickcoblentz.aws.models.VirtueAWSContext
import com.github.ajalt.clikt.core.*
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.nickcoblentz.aws.commands.CredentialReport
import com.nickcoblentz.aws.commands.Iam
import java.nio.file.Paths
import kotlin.io.path.Path

/**
 * Main CLI class for the KubePentest application.
 */
class CLI : CliktCommand(name = "java -jar virtueaws-all.jar") {
    // Global options
    override fun help(context: com.github.ajalt.clikt.core.Context) =
        "Command line utility to help in AWS pentesting"

    private val configPathOption by option("-c", "--config",
        help = "Path to aws credential file")
        .default(Paths.get(System.getProperty("user.home"), ".aws", "credentials").toString())

    private val profileOption by option("--profile", "-p",help="Profile to use from AWS Config").default("")

    private val outputDirectoryOption by option("-o", "--output-dir",
        help = "Output directory to save exported resources")
        .default("output")

    // Shared context object
    val config by findOrSetObject { VirtueAWSContext(Path(outputDirectoryOption),configPathOption,profileOption) }

    init {
        this.installMordantMarkdown()
    }

    override fun run() {

        config.toolDirectories.ensureOutputDirectoriesCreated()



    }
}


/**
 * Main entry point for the application
 */
fun main(args: Array<String>) = CLI().subcommands(
    Iam(),
    CredentialReport()
).main(args)
