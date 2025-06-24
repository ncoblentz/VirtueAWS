package com.nickcoblentz.aws.commands

import aws.sdk.kotlin.services.iam.IamClient
import aws.sdk.kotlin.services.iam.getGroupPolicy
import aws.sdk.kotlin.services.iam.getPolicy
import aws.sdk.kotlin.services.iam.getPolicyVersion
import aws.sdk.kotlin.services.iam.getUserPolicy
import aws.sdk.kotlin.services.iam.model.AttachedPolicy
import aws.sdk.kotlin.services.iam.model.Group
import aws.sdk.kotlin.services.iam.model.User
import aws.sdk.kotlin.services.iam.paginators.attachedPolicies
import aws.sdk.kotlin.services.iam.paginators.groups
import aws.sdk.kotlin.services.iam.paginators.listAttachedGroupPoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listAttachedUserPoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listGroupPoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listGroupsForUserPaginated
import aws.sdk.kotlin.services.iam.paginators.listUserPoliciesPaginated
import aws.sdk.kotlin.services.iam.paginators.listUsersPaginated
import aws.sdk.kotlin.services.iam.paginators.policyNames
import aws.sdk.kotlin.services.iam.paginators.users
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
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import java.net.URLDecoder
import kotlin.io.path.absolutePathString
import kotlin.io.path.writeText

class Iam : CliktCommand() {
    override fun help(context: com.github.ajalt.clikt.core.Context) = "Dumps key AWS resources"
    //val dumpConfig by option("--download","-d",help="Download and Analyzethe IAM Users, Groups, and Policies").flag()
    private val config by requireObject<VirtueAWSContext>()

    init {
        this.installMordantMarkdown()
    }

    override fun run() {


        config.toolDirectories.ensureOutputDirectoriesCreated()

//        if(dumpConfig) {
            runBlocking {
                dumpUsers()
            }
//        }
//        else if(analyze) {
//            analyzeUsers()
//        }
//        else {
//            config.prettyLogger.printlnSuccess("No option selected")
//        }

    }

    suspend fun dumpUsers() {
        config.getIamClient().use { iamClient ->
            config.prettyLogger.printlnInfo("Starting IAM user and policy export...")
            try {
                val iamExport = exportIamUsersAndPolicies(iamClient)
                val allUsers = iamExport.users
                val allPolicies = iamExport.policies
                val markdownBuilder : StringBuilder = StringBuilder()
                markdownBuilder.appendLine("## Users")
                markdownBuilder.appendLine("## Summary")

                markdownBuilder.appendLine(DataSerializer.toMarkdownTable(allUsers))

                allUsers.forEach { user ->
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

                    markdownBuilder.appendLine("### User: ${user.userName}")
                    markdownBuilder.appendLine("#### Groups")
                    markdownBuilder.appendLine(DataSerializer.toMarkdownTable(user.groups))
                    markdownBuilder.appendLine("#### Inline Policies")
                    markdownBuilder.appendLine(DataSerializer.toMarkdownTable(user.inlinePolicyNames))

                    markdownBuilder.appendLine("#### Combined Policies")
                    //markdownBuilder.appendLine("```\n```")



                    combinedPolicies.forEach { policy ->
                        markdownBuilder.appendLine("##### ${policy.policyName}: ${policy.policyIdentifier}")
                        markdownBuilder.appendLine("```json")
                        markdownBuilder.appendLine("${policy.policyDocument}")
                        markdownBuilder.appendLine("```")
                    }





                }

                //config.prettyLogger.printlnMarkdown(markdownBuilder.toString())
                listOf(ToolOutputExtension.CSV, ToolOutputExtension.JSON).forEach { ext ->
                    val policiesOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMPOLICIES,ext)
                    val usersOutputPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMUSERS,ext)

                    when(ext) {
                        ToolOutputExtension.JSON -> {
                            policiesOutputPath?.writeText(DataSerializer.toJson(iamExport.policies))
                            usersOutputPath?.writeText(DataSerializer.toJson(iamExport.users))
                        }
                        ToolOutputExtension.CSV -> {
                            policiesOutputPath?.writeText(DataSerializer.toCsv(iamExport.policies))
                            usersOutputPath?.writeText(DataSerializer.toCsv(iamExport.users))
                        }
                        else -> {}
                    }
                }


                val markdownPath = config.toolDirectories.outputFile(ToolOutputDirectory.IAMDIR, ToolOutputFile.IAMSUMMARY,ToolOutputExtension.MD)
                markdownPath?.writeText(markdownBuilder.toString())
                config.prettyLogger.printlnSuccess("Write output to: ${markdownPath?.absolutePathString()}")

            } catch (e: Exception) {
                config.prettyLogger.printlnError("An error occurred during the export process:",e.printStackTrace().toString())
            }


        }

    }

    suspend fun exportIamUsersAndPolicies(iamClient : IamClient): IamExport {
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
            val userInlinePolicyNames = processInlinePolicies(iamClient, userName, null, getUserInlinePolicies(iamClient, userName), discoveredPolicies)

            // --- Process policies from groups ---
            val groups = getGroupsForUser(iamClient, userName)
            val groupInfoList = mutableListOf<GroupInfo>()
            for (group in groups) {
                println("  -> Checking group: ${group.groupName}")
                val groupName = group.groupName
                val groupAttachedPolicyArns = processManagedPolicies(iamClient, getGroupAttachedPolicies(iamClient, groupName), discoveredPolicies)
                val groupInlinePolicyNames = processInlinePolicies(iamClient, null, groupName, getGroupInlinePolicies(iamClient, groupName), discoveredPolicies)

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


        val exportData = IamExport(
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

    /**
     * Processes a list of inline policies, adds them to the global cache, and returns their generated unique names.
     */
    private suspend fun processInlinePolicies(
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

}


/**
 * Data class to represent a single IAM user and their associated policies.
 * @param userName The friendly name of the IAM user.
 * @param userId The unique stable identifier for the user.
 * @param arn The Amazon Resource Name (ARN) for the user.
 * @param attachedPolicies A list of AWS managed policies attached to the user.
 * @param inlinePolicies A list of inline policies embedded in the user's profile.
 */
@Serializable
data class UserData(
    @CsvColumnMapping(name = "Username", order = 1)
    @JsonProperty("userName")
    val userName: String,

    @CsvColumnMapping(name = "User ID", order = 2)
    @JsonProperty("userId")
    val userId: String,

    @CsvColumnMapping(name = "ARN", order = 3)
    @JsonProperty("arn")
    val arn: String,

    @CsvColumnMapping(name = "Attached Policies", order = 4)
    @JsonProperty("attachedPolicyArns")
    val attachedPolicyArns: List<String>,

    @CsvColumnMapping(name = "Inline Policies", order = 5)
    @JsonProperty("inlinePolicyNames")
    val inlinePolicyNames: List<String>, // References policies by a unique generated name

    @CsvColumnMapping(name = "Groups", order = 6)
    @JsonProperty("groups")
    val groups: List<GroupInfo>


)

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

data class IamExport(
    val users: List<UserData>,
    val policies: List<PolicyDetail>
)
