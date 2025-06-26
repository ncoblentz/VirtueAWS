package com.nickcoblentz.aws.commands

import aws.sdk.kotlin.services.iam.IamClient
import aws.sdk.kotlin.services.iam.getGroupPolicy
import aws.sdk.kotlin.services.iam.getPolicy
import aws.sdk.kotlin.services.iam.getPolicyVersion
import aws.sdk.kotlin.services.iam.getRolePolicy
import aws.sdk.kotlin.services.iam.getUserPolicy
import aws.sdk.kotlin.services.iam.model.AttachedPolicy
import aws.sdk.kotlin.services.iam.model.Group
import aws.sdk.kotlin.services.iam.model.Role
import aws.sdk.kotlin.services.iam.model.User
import aws.sdk.kotlin.services.iam.paginators.attachedPolicies
import aws.sdk.kotlin.services.iam.paginators.groups
import aws.sdk.kotlin.services.iam.paginators.listAttachedGroupPoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listAttachedRolePoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listAttachedUserPoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listGroupPoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listGroupsForUserPaginated
import aws.sdk.kotlin.services.iam.paginators.listRolePoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listRolesPaginated
import aws.sdk.kotlin.services.iam.paginators.listUserPoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listUsersPaginated
import aws.sdk.kotlin.services.iam.paginators.policyNames
import aws.sdk.kotlin.services.iam.paginators.roles
import aws.sdk.kotlin.services.iam.paginators.users
import aws.sdk.kotlin.services.lambda.LambdaClient
import aws.sdk.kotlin.services.lambda.getFunction
import aws.sdk.kotlin.services.lambda.getFunctionConfiguration
import aws.sdk.kotlin.services.lambda.listFunctions
import aws.sdk.kotlin.services.lambda.model.FunctionConfiguration
import aws.sdk.kotlin.services.lambda.model.GetFunctionConfigurationResponse
import com.fasterxml.jackson.annotation.JsonProperty
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.installMordantMarkdown
import com.github.ajalt.clikt.core.requireObject
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.nickcoblentz.aws.models.ToolOutputDirectory
import com.nickcoblentz.aws.models.ToolOutputExtension
import com.nickcoblentz.aws.models.ToolOutputFile
import com.nickcoblentz.aws.models.VirtueAWSContext
import com.nickcoblentz.data.CsvColumnMapping
import com.nickcoblentz.data.DataSerializer
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.get
import io.ktor.http.ContentDisposition.Companion.File
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URLDecoder
import java.util.zip.ZipInputStream
import kotlin.collections.forEach
import kotlin.io.path.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.copyTo
import kotlin.io.path.createDirectories
import kotlin.io.path.createDirectory
import kotlin.io.path.inputStream
import kotlin.io.path.outputStream
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

class Iam : CliktCommand() {
    override fun help(context: com.github.ajalt.clikt.core.Context) = "Dumps key AWS resources"
    val dumpOption by option("--download","-d",help="Download the IAM Users, Groups, Roles, and Policies for Analysis").flag()
    val analyzeOption by option("--analyze","-e",help="Analyze IAM Users, Groups, Roles, and Policies").flag()
    private val config by requireObject<VirtueAWSContext>()

    init {
        this.installMordantMarkdown()
    }

    override fun run() {


        config.toolDirectories.ensureOutputDirectoriesCreated()

        if(dumpOption) {
            runBlocking {
                val asyncList =
                    mutableListOf(
                        //async { dumpUsers() },
                        //async { dumpRoles() },
                        async { dumpLambdas() }

                )

                asyncList.awaitAll()
            }
        }
        else if(analyzeOption) {
            analyze()
        }
        else {
            config.prettyLogger.printlnSuccess("No option selected")
        }

    }


    suspend fun dumpLambdas() {
        val allLambdas = mutableListOf<LambdaExport>()
        config.regions.forEach { region ->
                val allFunctions = listAllFunctions(region)
                allFunctions.forEach { function ->
                    function.functionName?.let { functionName ->
                        println("Processing $functionName in $region...")
                        val codeLocation = downloadAndUnzipFunction(functionName, region)
                        allLambdas.add(LambdaExport(region, function.functionName, codeLocation,function))
                    }
                }
        }

        val markdownBuilder : StringBuilder = StringBuilder()
        markdownBuilder.appendLine("## Lambdas")
        markdownBuilder.appendLine("### Summary")

        markdownBuilder.appendLine(DataSerializer.toMarkdownTable(allLambdas))


        listOf(ToolOutputExtension.CSV, ToolOutputExtension.JSON, ToolOutputExtension.MD).forEach { ext ->
            val outputPath = config.toolDirectories.outputFile(ToolOutputDirectory.LAMBDAANALYSIS, ToolOutputFile.LAMBDASUMMARY,ext)

            when(ext) {
                ToolOutputExtension.JSON -> {
                    outputPath?.writeText(DataSerializer.toJson(allLambdas))
                    config.prettyLogger.printlnSuccess("Write output to: ${outputPath?.absolutePathString()}")
                }
                ToolOutputExtension.CSV -> {
                    outputPath?.writeText(DataSerializer.toCsv(allLambdas))
                    config.prettyLogger.printlnSuccess("Write output to: ${outputPath?.absolutePathString()}")
                }
                ToolOutputExtension.MD -> {
                    outputPath?.writeText(markdownBuilder.toString())
                    config.prettyLogger.printlnSuccess("Write output to: ${outputPath?.absolutePathString()}")
                }
                else -> {}
            }
        }



    }

    suspend fun listAllFunctions(region : String): List<FunctionConfiguration> {
        config.getLambdaClient(region)?.use { lambdaClient ->
            val functions = mutableListOf<FunctionConfiguration>()
            var marker: String? = null

            do {
                val response = lambdaClient.listFunctions {
                    this.marker = marker
                }
                functions.addAll(response.functions ?: emptyList())
                marker = response.nextMarker
            } while (marker != null)

            return functions
        }
        return emptyList()
    }
/*
    suspend fun getFunctionConfiguration(functionName: String, region: String): GetFunctionConfigurationResponse? {
        config.getLambdaClient(region).use { lambdaClient ->
            return try {
                lambdaClient.getFunctionConfiguration {
                    this.functionName = functionName
                }
            } catch (e: Exception) {
                println("Error getting configuration for $functionName: ${e.message}")
                null
            }
        }
    }
*/
    suspend fun downloadAndUnzipFunction(functionName: String, region : String) : String? {
        config.getLambdaClient(region)?.use { lambdaClient ->
            val getFunctionResponse =
                try {
                    lambdaClient.getFunction { this.functionName = functionName }
                } catch (e: Exception) {
                    println("Error getting function details for $functionName: ${e.message}")
                    return null
                }

            val codeLocation = getFunctionResponse.code?.location ?: run {
                println("Could not find code location for $functionName")
                return null
            }

            // --- Ktor Client Usage Updated ---
            val zipContent: ByteArray = HttpClient(CIO).use { client ->
                client.get(codeLocation).body<ByteArray>()
            }
            // ---------------------------------

            val zipFile = Path(
                config.toolDirectories.outputDirectory(ToolOutputDirectory.LAMBDASOURCES).toString(),
                "$region-$functionName.zip"
            )
            zipFile.writeBytes(zipContent)

            println("Downloaded source for $functionName to ${zipFile.absolutePathString()}")

            // Unzip the file
            val destDir = Path(
                config.toolDirectories.outputDirectory(ToolOutputDirectory.LAMBDACODE).toString(),
                "$region-$functionName"
            )
            destDir.createDirectories()

            ZipInputStream(zipFile.inputStream()).use { zis ->
                var zipEntry = zis.nextEntry
                while (zipEntry != null) {
                    val newFilePath = Path(destDir.toString(), zipEntry.name)
                    newFilePath.createDirectory()
                    if (!zipEntry.isDirectory) {
                        newFilePath.createDirectory()
                        newFilePath.outputStream().use { output ->
                            zis.copyTo(output)
                        }
                    }
                    zipEntry = zis.nextEntry
                }
            }

            println("Unzipped source for $functionName to ${destDir.absolutePathString()}")
            return destDir.absolutePathString()
        }
        return null
    }

    fun analyze() {

        val rolePoliciesOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMROLEPOLICIES,ToolOutputExtension.JSON)
        val rolesOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMROLES,ToolOutputExtension.JSON)
        val userPoliciesOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMUSERPOLICIES,ToolOutputExtension.JSON)
        val usersOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMUSERS,ToolOutputExtension.JSON)


        if(rolesOutputPath!=null && rolePoliciesOutputPath!=null && userPoliciesOutputPath!=null && usersOutputPath!=null) {
            val allRoles = DataSerializer.fromJson(rolesOutputPath.readText(), RoleData::class.java)
            val allRolePolicies = DataSerializer.fromJson(rolePoliciesOutputPath.readText(), PolicyDetail::class.java)
            val allUsers = DataSerializer.fromJson(usersOutputPath.readText(), UserData::class.java)
            val allUsersPolicies = DataSerializer.fromJson(userPoliciesOutputPath.readText(), PolicyDetail::class.java)
            analyzeUsers(allUsers,allUsersPolicies)
            analyzeRoles(allRoles,allRolePolicies)

        }
    }

    fun analyzeRoles(allRoles: List<RoleData>, allPolicies: List<PolicyDetail>) {

        val markdownBuilder : StringBuilder = StringBuilder()
        markdownBuilder.appendLine("## Roles")
        markdownBuilder.appendLine("## Summary")

        markdownBuilder.appendLine(DataSerializer.toMarkdownTable(allRoles))

        allRoles.forEach { role ->
            val combinedPolicies = mutableListOf<PolicyDetail>()


            role.inlinePolicyNames.forEach { policyName ->
                val policy = allPolicies.find { it.policyName == policyName }
                policy?.let { combinedPolicies.add(it) }
            }

            role.attachedPolicyArns.forEach { arn ->
                val policy = allPolicies.find { it.policyIdentifier == arn }
                policy?.let { combinedPolicies.add(it) }
            }

            markdownBuilder.appendLine("### Role: [${role.roleName}](https://us-east-1.console.aws.amazon.com/iam/home?#/roles/details/${role.roleName})")
            markdownBuilder.appendLine("#### Attached Policies")
            markdownBuilder.appendLine(DataSerializer.toMarkdownTable(role.attachedPolicyArns))
            markdownBuilder.appendLine("#### Inline Policies")
            markdownBuilder.appendLine(DataSerializer.toMarkdownTable(role.inlinePolicyNames))
            markdownBuilder.appendLine("#### Combined Policies")



            combinedPolicies.forEach { policy ->
                markdownBuilder.appendLine("##### ${policy.policyName}: ${policy.policyIdentifier}")
                markdownBuilder.appendLine("```json")
                markdownBuilder.appendLine("${policy.policyDocument}")
                markdownBuilder.appendLine("```")
            }

        }

        val markdownPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMROLESUMMARY,ToolOutputExtension.MD)
        markdownPath?.writeText(markdownBuilder.toString())
        config.prettyLogger.printlnSuccess("Write output to: ${markdownPath?.absolutePathString()}")
    }

    fun analyzeUsers(allUsers:List<UserData>, allPolicies:List<PolicyDetail>) {

        val analyzedUsers = allUsers.map { AnalyzedUser(it)}

        analyzedUsers.forEach { user ->
            val combinedPolicies = mutableListOf<PolicyDetail>()

            user.inlinePolicyNames.forEach { policyName ->
                val policy = allPolicies.find { it.policyName == policyName }
                policy?.let { combinedPolicies.add(it) }
            }

            user.attachedPolicyArns.forEach { arn ->
                val policy = allPolicies.find { it.policyIdentifier == arn }
                policy?.let { combinedPolicies.add(it) }
            }

            user.groups.forEach { group ->
                group.attachedPolicyArns.forEach { arn ->
                    val policy = allPolicies.find { it.policyIdentifier == arn }
                    policy?.let { combinedPolicies.add(it) }
                }

                group.inlinePolicyNames.forEach { policyName ->
                    val policy = allPolicies.find { it.policyIdentifier == policyName }
                    policy?.let { combinedPolicies.add(it) }
                }
            }

            analyzePermissions(user,combinedPolicies)


        }

        val markdownPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.ANALYZEDUSERS,ToolOutputExtension.MD)
        val csvPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.ANALYZEDUSERS,ToolOutputExtension.CSV)
        val jsonPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.ANALYZEDUSERS,ToolOutputExtension.JSON)
        markdownPath?.writeText(DataSerializer.toMarkdownTable(analyzedUsers))
        config.prettyLogger.printlnSuccess("Write output to: ${markdownPath?.absolutePathString()}")

        csvPath?.writeText(DataSerializer.toMarkdownTable(analyzedUsers))
        config.prettyLogger.printlnSuccess("Write output to: ${csvPath?.absolutePathString()}")

        jsonPath?.writeText(DataSerializer.toMarkdownTable(analyzedUsers))
        config.prettyLogger.printlnSuccess("Write output to: ${jsonPath?.absolutePathString()}")
    }



        suspend fun dumpRoles() {
        val allRolesData = mutableListOf<RoleData>()
        val discoveredPolicies = mutableMapOf<String, PolicyDetail>() // Global policy cache <Identifier, Detail>

        config.getIamClient().use { iamClient ->
            println("Fetching all IAM roles...")
            val roles = getAllRoles(iamClient)
            println("Found ${roles.size} roles. Now fetching policies for each role...")

            for ((index, role) in roles.withIndex()) {
                val roleName = role.roleName
                println("Processing role ${index + 1}/${roles.size}: $roleName")

                // --- Process policies attached to the role ---
                val attachedPolicies = getRoleAttachedPolicies(iamClient, roleName)
                val attachedPolicyArns = processManagedPolicies(iamClient, attachedPolicies, discoveredPolicies)

                // --- Process inline policies for the role ---
                val inlinePolicyNamesList = getRoleInlinePolicies(iamClient, roleName)
                val inlinePolicyNames = processInlineRolePolicies(iamClient, roleName, inlinePolicyNamesList, discoveredPolicies)

                val assumeRolePolicyDoc = role.assumeRolePolicyDocument?.let {
                    URLDecoder.decode(it, "UTF-8")
                }



                allRolesData.add(
                    RoleData(
                        roleName = roleName,
                        roleId = role.roleId,
                        arn = role.arn,
                        assumeRolePolicyDocument = assumeRolePolicyDoc,
                        attachedPolicyArns = attachedPolicyArns,
                        inlinePolicyNames = inlinePolicyNames
                    )
                )
            }
        }

        val iamExport = IamRolesAndPoliciesExport(
            roles = allRolesData,
            policies = discoveredPolicies.values.toList().sortedBy { it.policyName }
        )

        val allPolicies = iamExport.policies
        val markdownBuilder : StringBuilder = StringBuilder()
        markdownBuilder.appendLine("## Roles")
        markdownBuilder.appendLine("## Summary")

        markdownBuilder.appendLine(DataSerializer.toMarkdownTable(iamExport.roles))

        iamExport.roles.forEach { role ->
            val combinedPolicies = mutableListOf<PolicyDetail>()


            role.inlinePolicyNames.forEach { policyName ->
                val policy = allPolicies.find { it.policyName == policyName }
                policy?.let { combinedPolicies.add(it) }
            }

            role.attachedPolicyArns.forEach { arn ->
                val policy = allPolicies.find { it.policyIdentifier == arn }
                policy?.let { combinedPolicies.add(it) }
            }

            markdownBuilder.appendLine("### Role: [${role.roleName}](https://us-east-1.console.aws.amazon.com/iam/home?#/roles/details/${role.roleName})")
            markdownBuilder.appendLine("#### Attached Policies")
            markdownBuilder.appendLine(DataSerializer.toMarkdownTable(role.attachedPolicyArns))
            markdownBuilder.appendLine("#### Inline Policies")
            markdownBuilder.appendLine(DataSerializer.toMarkdownTable(role.inlinePolicyNames))
            markdownBuilder.appendLine("#### Combined Policies")



            combinedPolicies.forEach { policy ->
                markdownBuilder.appendLine("##### ${policy.policyName}: ${policy.policyIdentifier}")
                markdownBuilder.appendLine("```json")
                markdownBuilder.appendLine("${policy.policyDocument}")
                markdownBuilder.appendLine("```")
            }

        }

        //config.prettyLogger.printlnMarkdown(markdownBuilder.toString())
        listOf(ToolOutputExtension.CSV, ToolOutputExtension.JSON).forEach { ext ->
            val policiesOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMROLEPOLICIES,ext)
            val rolesOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMROLES,ext)

            when(ext) {
                ToolOutputExtension.JSON -> {
                    policiesOutputPath?.writeText(DataSerializer.toJson(iamExport.policies))
                    rolesOutputPath?.writeText(DataSerializer.toJson(iamExport.roles))
                }
                ToolOutputExtension.CSV -> {
                    policiesOutputPath?.writeText(DataSerializer.toCsv(iamExport.policies))
                    rolesOutputPath?.writeText(DataSerializer.toCsv(iamExport.roles))
                }
                else -> {}
            }
        }


        val markdownPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMROLESUMMARY,ToolOutputExtension.MD)
        markdownPath?.writeText(markdownBuilder.toString())
        config.prettyLogger.printlnSuccess("Write output to: ${markdownPath?.absolutePathString()}")


    }

    suspend fun dumpUsers() {
        config.getIamClient().use { iamClient ->
            config.prettyLogger.printlnInfo("Starting IAM user and policy export...")
            try {
                val iamExport = exportIamUsersAndPolicies(iamClient)
                val allUsers = iamExport.users
                val allPolicies = iamExport.policies

                listOf(ToolOutputExtension.CSV, ToolOutputExtension.JSON).forEach { ext ->
                    val policiesOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMUSERPOLICIES,ext)
                    val usersOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMUSERS,ext)

                    when(ext) {
                        ToolOutputExtension.JSON -> {
                            policiesOutputPath?.writeText(DataSerializer.toJson(iamExport.policies))
                            config.prettyLogger.printlnSuccess("Wrote output to: ${policiesOutputPath?.absolutePathString()}")
                            usersOutputPath?.writeText(DataSerializer.toJson(iamExport.users))
                            config.prettyLogger.printlnSuccess("Wrote output to: ${usersOutputPath?.absolutePathString()}")
                        }
                        ToolOutputExtension.CSV -> {
                            policiesOutputPath?.writeText(DataSerializer.toCsv(iamExport.policies))
                            config.prettyLogger.printlnSuccess("Wrote output to: ${policiesOutputPath?.absolutePathString()}")
                            usersOutputPath?.writeText(DataSerializer.toCsv(iamExport.users))
                            config.prettyLogger.printlnSuccess("Wrote output to: ${usersOutputPath?.absolutePathString()}")
                        }
                        else -> {}
                    }
                }


            } catch (e: Exception) {
                config.prettyLogger.printlnError("An error occurred during the export process:",e.printStackTrace().toString())
            }


        }

    }

    suspend fun exportIamUsersAndPolicies(iamClient : IamClient): IamUsersAndPoliciesExport {
        val allUsersData = mutableListOf<UserData>()
        val discoveredPolicies = mutableMapOf<String, PolicyDetail>() // Global policy cache <Identifier, Detail>


        println("Fetching all IAM users...")
        val users = getAllUsers(iamClient)
        println("Found ${users.size} users. Now fetching policies for each user...")

        for ((index, user) in users.withIndex()) {
            val userName = user.userName
            println("Processing user ${index + 1}/${users.size}: $userName")

            // --- Process policies directly on the user ---
            val userAttachedPolicyArns = processManagedPolicies(iamClient, getUserAttachedPolicies(iamClient, userName), discoveredPolicies)
            val userInlinePolicyNames = processInlineUserPolicies(iamClient, userName, null, getUserInlinePolicies(iamClient, userName), discoveredPolicies)

            // --- Process policies from groups ---
            val groups = getGroupsForUser(iamClient, userName)
            val groupInfoList = mutableListOf<GroupInfo>()
            for (group in groups) {
                println("  -> Checking group: ${group.groupName}")
                val groupName = group.groupName
                val groupAttachedPolicyArns = processManagedPolicies(iamClient, getGroupAttachedPolicies(iamClient, groupName), discoveredPolicies)
                val groupInlinePolicyNames = processInlineUserPolicies(iamClient, null, groupName, getGroupInlinePolicies(iamClient, groupName), discoveredPolicies)

                groupInfoList.add(GroupInfo(groupName, groupAttachedPolicyArns, groupInlinePolicyNames))
            }

            allUsersData.add(
                UserData(
                    userName = userName,
                    userId = user.userId,
                    arn = user.arn,
                    attachedPolicyArns = userAttachedPolicyArns,
                    inlinePolicyNames = userInlinePolicyNames,
                    groups = groupInfoList
                )
            )
        }


        val exportData = IamUsersAndPoliciesExport(
            users = allUsersData,
            policies = discoveredPolicies.values.toList().sortedBy { it.policyName }
        )

        return exportData
    }


    /**
     * Processes a list of managed policies, adds them to the global cache if new, and returns their ARNs.
     */
    private suspend fun processManagedPolicies(
        iamClient: IamClient,
        policies: List<AttachedPolicy>,
        discoveredPolicies: MutableMap<String, PolicyDetail>
    ): List<String> {
        val policyArns = mutableListOf<String>()
        for (policy in policies) {
            val policyArn = policy.policyArn!!
            policyArns.add(policyArn)
            if (!discoveredPolicies.containsKey(policyArn)) {
                // Step 1: Get the policy metadata to find its default version ID.
                val policyResponse = iamClient.getPolicy { this.policyArn = policyArn }.policy!!
                val versionId = policyResponse.defaultVersionId!!

                // Step 2: Get the specific policy version to retrieve its document.
                val policyVersionResponse = iamClient.getPolicyVersion {
                    this.policyArn = policyArn
                    this.versionId = versionId
                }

                // The policy document is URL-encoded, so it must be decoded.
                val policyDocument = policyVersionResponse.policyVersion?.document?.let {
                    URLDecoder.decode(it, "UTF-8")
                }

                discoveredPolicies[policyArn] = PolicyDetail(
                    policyName = policyResponse.policyName!!,
                    policyIdentifier = policyArn,
                    policyId = policyResponse.policyId,
                    isAwsManaged = policyArn.startsWith("arn:aws:iam::aws:policy/"),
                    policyDocument = policyDocument
                )
            }
        }
        return policyArns
    }


    private suspend fun processInlineRolePolicies(
        iamClient: IamClient,
        roleName: String,
        policyNames: List<String>,
        discoveredPolicies: MutableMap<String, PolicyDetail>
    ): List<String> {
        val uniquePolicyNames = mutableListOf<String>()
        for (policyName in policyNames) {
            val uniqueIdentifier = "inline-policy/role/$roleName/$policyName"
            uniquePolicyNames.add(uniqueIdentifier)

            if (!discoveredPolicies.containsKey(uniqueIdentifier)) {
                val policyDoc = iamClient.getRolePolicy {
                    this.roleName = roleName
                    this.policyName = policyName
                }.policyDocument

                // Inline policy documents are NOT URL-encoded, so we can use them directly.
                discoveredPolicies[uniqueIdentifier] = PolicyDetail(
                    policyName = policyName,
                    policyIdentifier = uniqueIdentifier,
                    policyId = null, // No policy ID for inline policies
                    isAwsManaged = false,
                    policyDocument = policyDoc
                )
            }
        }
        return uniquePolicyNames
    }

    /**
     * Processes a list of inline policies, adds them to the global cache, and returns their generated unique names.
     */
    private suspend fun processInlineUserPolicies(
        iamClient: IamClient,
        userName: String?,
        groupName: String?,
        policyNames: List<String>,
        discoveredPolicies: MutableMap<String, PolicyDetail>
    ): List<String> {
        val uniquePolicyNames = mutableListOf<String>()
        val entityName = userName ?: groupName!!
        val entityType = if (userName != null) "user" else "group"

        for (policyName in policyNames) {
            val uniqueIdentifier = "inline-policy/$entityType/$entityName/$policyName"
            uniquePolicyNames.add(uniqueIdentifier)

            if (!discoveredPolicies.containsKey(uniqueIdentifier)) {
                val policyDoc = when(entityType) {
                    "user" -> URLDecoder.decode(iamClient.getUserPolicy { this.userName = userName; this.policyName = policyName }.policyDocument,"UTF-8")
                    "group" -> URLDecoder.decode(iamClient.getGroupPolicy { this.groupName = groupName; this.policyName = policyName }.policyDocument,"UTF-8")
                    else -> null
                }

                discoveredPolicies[uniqueIdentifier] = PolicyDetail(
                    policyName = policyName,
                    policyIdentifier = uniqueIdentifier,
                    policyId = null, // No policy ID for inline policies
                    isAwsManaged = false,
                    policyDocument = policyDoc
                )
            }
        }
        return uniquePolicyNames
    }

    private suspend fun getAllUsers(iamClient: IamClient): List<User> =
        iamClient.listUsersPaginated {}.users().toList()

    private suspend fun getUserAttachedPolicies(iamClient: IamClient, userName: String): List<AttachedPolicy> =
        iamClient.listAttachedUserPoliciesPaginated { this.userName = userName }.attachedPolicies().toList()

    private suspend fun getUserInlinePolicies(iamClient: IamClient, userName: String): List<String> =
        iamClient.listUserPoliciesPaginated { this.userName = userName }.policyNames().toList()

    private suspend fun getGroupsForUser(iamClient: IamClient, userName: String): List<Group> =
        iamClient.listGroupsForUserPaginated { this.userName = userName }.groups().toList()

    private suspend fun getGroupAttachedPolicies(iamClient: IamClient, groupName: String): List<AttachedPolicy> =
        iamClient.listAttachedGroupPoliciesPaginated { this.groupName = groupName }.attachedPolicies().toList()

    private suspend fun getGroupInlinePolicies(iamClient: IamClient, groupName: String): List<String> =
        iamClient.listGroupPoliciesPaginated { this.groupName = groupName }.policyNames().toList()

    private suspend fun getAllRoles(iamClient: IamClient): List<Role> =
        iamClient.listRolesPaginated {}.roles().toList()

    private suspend fun getRoleAttachedPolicies(iamClient: IamClient, roleName: String): List<AttachedPolicy> =
        iamClient.listAttachedRolePoliciesPaginated { this.roleName = roleName }.attachedPolicies().toList()

    private suspend fun getRoleInlinePolicies(iamClient: IamClient, roleName: String): List<String> =
        iamClient.listRolePoliciesPaginated { this.roleName = roleName }.policyNames().toList()


    private fun analyzePermissions(entity : RoleAnalysisInterface,policies : List<PolicyDetail>) {
        val starStar="*"
        val iamStar="iam:*"
        val iamPassRole="iam:passrole"
        val stsAssumeRole="sts:assumerole"

        policies.forEach { policy ->
            if(!entity.hasStartStar && policyContains(starStar,"*",policy)) {
                entity.hasStartStar = true
                entity.hasIamStar = true
                entity.hasIamPassRole = true
            }

            if(!entity.hasIamStar && policyContains(iamStar,"*",policy)) {
                entity.hasIamStar = true
                entity.hasIamPassRole = true
            }

            if(!entity.hasIamPassRole && policyContains(iamPassRole,"*",policy)) {
                entity.hasIamPassRole = true
            }




        }


    }

    private fun policyContains(action : String,resource : String, policyDetail : PolicyDetail) : Boolean {
        policyDetail.policyDocument?.let { policyDocument ->

            val json = Json { ignoreUnknownKeys = true }

            try {
                val policy = json.parseToJsonElement(policyDocument).jsonObject

                val statement = policy["Statement"] ?: return false

                val statementArray = when (statement) {
                    is JsonArray -> statement
                    is JsonObject -> buildJsonArray { add(statement) }
                    else -> return false
                }

                for (stmt in statementArray.jsonArray) {
                    if (stmt !is JsonObject) continue

                    val effect = stmt["Effect"]?.jsonPrimitive?.contentOrNull
                    if (effect != "Allow") {
                        continue
                    }

                    val actionElement = stmt["Action"]
                    val resourceElement = stmt["Resource"]

                    val hasMatchingAction = when (actionElement) {
                        is JsonPrimitive -> actionElement.content.equals(action,true)
                        is JsonArray -> actionElement.jsonArray.any { it is JsonPrimitive && it.content.equals(action,true) }
                        else -> false
                    }

                    val hasMatchingResource = when (resourceElement) {
                        is JsonPrimitive -> resourceElement.content.equals(resource,true)
                        is JsonArray -> resourceElement.jsonArray.any { it is JsonPrimitive && it.content.equals(resource,true) }
                        else -> false
                    }

                    return (hasMatchingAction && hasMatchingResource)
                }
            } catch (e: Exception) {
                // Handle potential JSON parsing errors
                config.prettyLogger.printlnError("Error parsing policy JSON: ${e.message}",e.stackTrace.joinToString("\n"))
            }
        }
        return false
    }
}


/**
 * Data class to represent a single IAM user and their associated policies.
 * @param userName The friendly name of the IAM user.
 * @param userId The unique stable identifier for the user.
 * @param arn The Amazon Resource Name (ARN) for the user.
 * @param attachedPolicies A list of AWS managed policies attached to the user.
 * @param inlinePolicies A list of inline policies embedded in the user's profile.
 */

interface UserInterface {
    val userName: String
    val userId: String
    val arn: String
    val attachedPolicyArns: List<String>
    val inlinePolicyNames: List<String>
    val groups: List<GroupInfo>
}

data class UserData(
    @CsvColumnMapping(name = "Username", order = 1)
    @JsonProperty("userName")
    override val userName: String,

    @CsvColumnMapping(name = "User ID", order = 2)
    @JsonProperty("userId")
    override val userId: String,

    @CsvColumnMapping(name = "ARN", order = 3)
    @JsonProperty("arn")
    override val arn: String,

    @CsvColumnMapping(name = "Attached Policies", order = 4)
    @JsonProperty("attachedPolicyArns")
    override val attachedPolicyArns: List<String>,

    @CsvColumnMapping(name = "Inline Policies", order = 5)
    @JsonProperty("inlinePolicyNames")
    override val inlinePolicyNames: List<String>, // References policies by a unique generated name

    @CsvColumnMapping(name = "Groups", order = 6)
    @JsonProperty("groups")
    override val groups: List<GroupInfo>
) : UserInterface

/**
 * Represents a group a user belongs to and references the policies attached to that group.
 */
data class GroupInfo(
    @CsvColumnMapping(name = "Name", order = 1)
    @JsonProperty("groupName")
    val groupName: String,

    @CsvColumnMapping(name = "Attached Policies", order = 2)
    @JsonProperty("attachedPolicyArns")
    val attachedPolicyArns: List<String>,

    @CsvColumnMapping(name = "Inline Policies", order = 3)
    @JsonProperty("inlinePolicyNames")
    val inlinePolicyNames: List<String> // References policies by a unique generated name
)

/**
 * Represents the detailed information about a single unique IAM policy.
 * This is part of the global list.
 * @param policyName The friendly name of the policy.
 * @param policyIdentifier A unique identifier. For managed policies, this is the ARN. For inline policies, this is a generated unique name.
 * @param policyId The stable, unique ID of a managed policy. Null for inline policies.
 * @param isAwsManaged True if the policy is managed by AWS.
 * @param policyDocument The JSON policy document. Always populated for inline policies.
 */
data class PolicyDetail(

    @CsvColumnMapping(name = "Name", order = 1)
    @JsonProperty("policyName")
    val policyName: String,

    @CsvColumnMapping(name = "Identifier", order = 2)
    @JsonProperty("policyIdentifier")
    val policyIdentifier: String,

    @CsvColumnMapping(name = "ID", order = 3)
    @JsonProperty("policyId")
    val policyId: String?,

    @CsvColumnMapping(name = "Built-In Policy", order = 4)
    @JsonProperty("isAwsManaged")
    val isAwsManaged: Boolean,

    @CsvColumnMapping(name = "Document", order = 5)
    @JsonProperty("policyDocument")
    val policyDocument: String?
)

/**
 * Data class to represent an IAM policy.
 * @param policyName The name of the policy.
 * @param policyArn The ARN of the policy. For inline policies, this will be constructed manually.
 */

data class PolicyData(
    @CsvColumnMapping(name = "Name", order = 1)
    @JsonProperty("policyName")
    val policyName: String,

    @CsvColumnMapping(name = "ARN", order = 2)
    @JsonProperty("policyArn")
    val policyArn: String? = null,

    @CsvColumnMapping(name = "Document", order = 3)
    @JsonProperty("policyDocument")
    val policyDocument: String? = null // For inline policies
)

data class RoleData(

    @CsvColumnMapping(name = "Role Name", order = 1)
    @JsonProperty("roleName")
    val roleName: String,

    @CsvColumnMapping(name = "Role ID", order = 2)
    @JsonProperty("roleId")
    val roleId: String,

    @CsvColumnMapping(name = "Arn", order = 3)
    @JsonProperty("arn")
    val arn: String,

    @CsvColumnMapping(name = "Attached Policies", order = 4)
    @JsonProperty("attachedPolicyArns")
    val attachedPolicyArns: List<String>,

    @CsvColumnMapping(name = "Inline Policies", order = 5)
    @JsonProperty("inlinePolicyNames")
    val inlinePolicyNames: List<String>,

    @CsvColumnMapping(name = "Trust Relationships", order = 6)
    @JsonProperty("assumeRolePolicyDocument")
    val assumeRolePolicyDocument: String?

)

data class IamUsersAndPoliciesExport(
    @CsvColumnMapping(name = "Users", order = 1)
    @JsonProperty("users")
    val users: List<UserData>,

    @CsvColumnMapping(name = "Policies", order = 2)
    @JsonProperty("policies")
    val policies: List<PolicyDetail>,

)

data class IamRolesAndPoliciesExport(

    @CsvColumnMapping(name = "Policies", order = 1)
    @JsonProperty("policies")
    val policies: List<PolicyDetail>,

    @CsvColumnMapping(name = "Roles", order = 2)
    @JsonProperty("roles")
    val roles: List<RoleData>
)

data class AnalyzedUser(
    @CsvColumnMapping(name = "Username", order = 1)
    @JsonProperty("userName")
    override val userName: String,

    @CsvColumnMapping(name = "User ID", order = 2)
    @JsonProperty("userId")
    override val userId: String,

    @CsvColumnMapping(name = "ARN", order = 3)
    @JsonProperty("arn")
    override val arn: String,

    @CsvColumnMapping(name = "Attached Policies", order = 4)
    @JsonProperty("attachedPolicyArns")
    override val attachedPolicyArns: List<String>,

    @CsvColumnMapping(name = "Inline Policies", order = 5)
    @JsonProperty("inlinePolicyNames")
    override val inlinePolicyNames: List<String>, // References policies by a unique generated name

    @CsvColumnMapping(name = "Groups", order = 6)
    @JsonProperty("groups")
    override val groups: List<GroupInfo>,

    @CsvColumnMapping(name = "iam:*", order = 7)
    @JsonProperty("hasIamStar")
    override var hasIamStar: Boolean,

    @CsvColumnMapping(name = "iam:passRole", order = 8)
    @JsonProperty("hasIamStar")
    override var hasIamPassRole: Boolean,

    @CsvColumnMapping(name = "*:*", order = 8)
    @JsonProperty("hasStartStar")
    override var hasStartStar: Boolean,

    @CsvColumnMapping(name = "sts:AssumeRole", order = 9)
    @JsonProperty("hasStsAssumeRole")
    override var hasStsAssumeRole: Boolean,

    override var resourcesAllowedToAssumeRole: List<String>



) : UserInterface, RoleAnalysisInterface {
    constructor(user : UserData) : this(user.userName,user.userId,user.arn,user.attachedPolicyArns,user.inlinePolicyNames,user.groups,false,false,false,false,mutableListOf())
}

interface RoleAnalysisInterface {
    val inlinePolicyNames: List<String>
    val attachedPolicyArns: List<String>
    var hasIamStar: Boolean
    var hasIamPassRole: Boolean
    var hasStartStar: Boolean
    var hasStsAssumeRole: Boolean
    var resourcesAllowedToAssumeRole: List<String>
}

data class LambdaExport (
    @CsvColumnMapping(name = "Region", order = 1)
    @JsonProperty("region")
    val region : String,

    @CsvColumnMapping(name = "Name", order = 2)
    @JsonProperty("name")
    val name : String? = null,

    @CsvColumnMapping(name = "Code Location", order = 3)
    @JsonProperty("codeLocation")
    val codeLocation: String? = null,

    @CsvColumnMapping(name = "Configuration", order = 3)
    @JsonProperty("functionConfiguration")
    val functionConfiguration : FunctionConfiguration? = null
)