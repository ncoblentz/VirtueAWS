package com.nickcoblentz.aws.models

import aws.sdk.kotlin.runtime.auth.credentials.ProfileCredentialsProvider
import aws.sdk.kotlin.services.iam.IamClient
import com.nickcoblentz.kubepentest.utils.PrettyLogger
import java.nio.file.Path
import kotlin.io.path.Path

/**
 * Class to hold configuration and shared resources for the application.
 */
class VirtueAWSContext(outputBaseDirectoryPath : Path, val awsConfigPath : String, val profile: String) {
    var verbose: Boolean = false


    val toolDirectories = ToolDirectories( Path("."),outputBaseDirectoryPath)

    val prettyLogger: PrettyLogger = PrettyLogger()


    init {
        ToolOutputDirectory.values().forEach { toolOutputDirectory ->
            if(toolOutputDirectory.name!="BASE")
                toolDirectories.withNewOutputDirectory(toolOutputDirectory)
        }
        toolDirectories.ensureOutputDirectoriesCreated()
    }

    fun getIamClient() : IamClient {
        prettyLogger.printlnInfo("Using AWS profile: $profile")
        val client = IamClient {
            region="aws-global"
            credentialsProvider = ProfileCredentialsProvider(profileName = profile)
        }

        return client
    }
}
