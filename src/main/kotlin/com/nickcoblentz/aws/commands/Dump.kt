package com.nickcoblentz.aws.commands

import aws.sdk.kotlin.services.iam.IamClient
import aws.sdk.kotlin.services.iam.listGroups
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.installMordantMarkdown
import com.github.ajalt.clikt.core.requireObject
import com.nickcoblentz.aws.models.ToolOutputDirectory
import com.nickcoblentz.aws.models.VirtueAWSContext
import kotlinx.coroutines.runBlocking

class Dump : CliktCommand() {
    override fun help(context: com.github.ajalt.clikt.core.Context) = "Dumps key AWS resources"

    private val config by requireObject<VirtueAWSContext>()

    init {
        this.installMordantMarkdown()
    }

    override fun run() {


        config.toolDirectories.ensureOutputDirectoriesCreated()

        runBlocking {
            dumpUsers()
        }

    }

    suspend fun dumpUsers() {
        IamClient {region="aws-global"}.use { iamClient ->
            val response = iamClient.listUsers()
            response.users.forEach { user ->
                println(user.userName)
                
            }


        }
    }
}