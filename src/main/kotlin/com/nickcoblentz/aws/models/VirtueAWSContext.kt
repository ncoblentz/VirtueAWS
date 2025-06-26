package com.nickcoblentz.aws.models

import aws.sdk.kotlin.runtime.auth.credentials.ProfileCredentialsProvider
import aws.sdk.kotlin.services.iam.IamClient
import aws.sdk.kotlin.services.lambda.LambdaClient
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

    fun getLambdaClient(region : String) : LambdaClient? {
        prettyLogger.printlnInfo("Using AWS profile: $profile, region: $region")
        try {
            val client = LambdaClient {
                this.region = region
                credentialsProvider = ProfileCredentialsProvider(profileName = profile)
            }

            return client
        }catch (e : Exception){
            prettyLogger.printlnInfo("Exception in AWS profile: $profile, region: $region")
        }
        return null
    }

    val regions = listOf<String>("us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
//        "af-south-1",
//        "ap-east-1",
//        "ap-south-2",
//        "ap-southeast-3",
//        "ap-southeast-5",
//        "ap-southeast-4",
//        "ap-south-1",
//        "ap-northeast-3",
//        "ap-northeast-2",
//        "ap-southeast-1",
//        "ap-southeast-2",
//        "ap-east-2",
//        "ap-southeast-7",
//        "ap-northeast-1",
//        "ca-central-1",
//        "ca-west-1",
        "eu-central-1",
        "eu-west-1",
        "eu-west-2",
//        "eu-south-1",
        "eu-west-3",
//        "eu-south-2",
        "eu-north-1",
//        "eu-central-2",
//        "il-central-1",
//        "mx-central-1",
//        "me-south-1",
//        "me-central-1",
        "sa-east-1")
}
