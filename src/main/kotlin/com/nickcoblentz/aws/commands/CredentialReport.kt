package com.nickcoblentz.aws.commands

import aws.sdk.kotlin.services.iam.model.GenerateCredentialReportRequest
import aws.sdk.kotlin.services.iam.model.GetCredentialReportRequest
import aws.sdk.kotlin.services.iam.model.ReportStateType
import com.fasterxml.jackson.annotation.JsonProperty
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.installMordantMarkdown
import com.github.ajalt.clikt.core.requireObject
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.nickcoblentz.aws.models.ToolOutputExtension
import com.nickcoblentz.aws.models.ToolOutputFile
import com.nickcoblentz.aws.models.ToolOutputDirectory
import com.nickcoblentz.aws.models.VirtueAWSContext
import com.nickcoblentz.data.CsvColumnMapping
import com.nickcoblentz.data.DataSerializer
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit
import kotlin.io.path.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.appendText
import kotlin.io.path.exists
import kotlin.io.path.writeText
import kotlin.math.round

data class IamCredentialReportEntry(
    @CsvColumnMapping(name = "user", order = 1)
    @JsonProperty("user")
    val user: String,

    @CsvColumnMapping(name = "arn", order = 2)
    @JsonProperty("arn")
    val arn: String,

    @CsvColumnMapping(name = "user_creation_time", order = 2)
    @JsonProperty("userCreationTime")
    val userCreationTime: LocalDateTime?,

    @CsvColumnMapping(name = "password_enabled", order = 3)
    @JsonProperty("passwordEnabled")
    val passwordEnabled: Boolean,

    @CsvColumnMapping(name = "password_last_used", order = 4)
    @JsonProperty("passwordLastUsed")
    val passwordLastUsed: LocalDateTime?,

    @CsvColumnMapping(name = "password_last_changed", order = 5)
    @JsonProperty("passwordLastChanged")
    val passwordLastChanged: LocalDateTime?,

    @CsvColumnMapping(name = "password_next_rotation", order = 6)
    @JsonProperty("passwordNextRotation")
    val passwordNextRotation: String?, // Can be a date or 'not_supported'

    @CsvColumnMapping(name = "mfa_active", order = 7)
    @JsonProperty("mfaActive")
    val mfaActive: Boolean,

    @CsvColumnMapping(name = "access_key_1_active", order = 8)
    @JsonProperty("accessKey1Active")
    val accessKey1Active: Boolean,

    @CsvColumnMapping(name = "access_key_1_last_rotated", order = 9)
    @JsonProperty("accessKey1LastRotated")
    val accessKey1LastRotated: LocalDateTime?,

    @CsvColumnMapping(name = "access_key_1_last_used_date", order = 10)
    @JsonProperty("accessKey1LastUsedDate")
    val accessKey1LastUsedDate: LocalDateTime?,

    @CsvColumnMapping(name = "access_key_1_last_used_region", order = 11)
    @JsonProperty("accessKey1LastUsedRegion")
    val accessKey1LastUsedRegion: String?,

    @CsvColumnMapping(name = "access_key_1_last_used_service", order = 12)
    @JsonProperty("accessKey1LastUsedService")
    val accessKey1LastUsedService: String?,

    @CsvColumnMapping(name = "access_key_2_active", order = 13)
    @JsonProperty("accessKey2Active")
    val accessKey2Active: Boolean,

    @CsvColumnMapping(name = "access_key_2_last_rotated", order = 14)
    @JsonProperty("accessKey2LastRotated")
    val accessKey2LastRotated: LocalDateTime?,

    @CsvColumnMapping(name = "access_key_2_last_used_date", order = 15)
    @JsonProperty("accessKey2LastUsedDate")
    val accessKey2LastUsedDate: LocalDateTime?,

    @CsvColumnMapping(name = "access_key_2_last_used_region", order = 16)
    @JsonProperty("accessKey2LastUsedRegion")
    val accessKey2LastUsedRegion: String?,

    @CsvColumnMapping(name = "access_key_2_last_used_service", order = 17)
    @JsonProperty("accessKey2LastUsedService")
    val accessKey2LastUsedService: String?,

    @CsvColumnMapping(name = "cert_1_active", order = 18)
    @JsonProperty("cert1Active")
    val cert1Active: Boolean,

    @CsvColumnMapping(name = "cert_1_last_rotated", order = 19)
    @JsonProperty("cert1LastRotated")
    val cert1LastRotated: LocalDateTime?,

    @CsvColumnMapping(name = "cert_2_active", order = 20)
    @JsonProperty("cert2Active")
    val cert2Active: Boolean,

    @CsvColumnMapping(name = "cert_2_last_rotated", order = 21)
    @JsonProperty("cert2LastRotated")
    val cert2LastRotated: LocalDateTime?,

    @CsvColumnMapping(name = "Active User", order = 22)
    @JsonProperty("activeUser")
    var activeUser: Boolean = false,

    @CsvColumnMapping(name = "Years Since Last Login", order = 23)
    @JsonProperty("yearsSinceLastLogin")
    var yearsSinceLastLogin: Double? = null,

    @CsvColumnMapping(name = "Uses Password But MFA Not Enabled", order = 24)
    @JsonProperty("usesPasswordButMFANotEnabled")
    var usesPasswordButMFANotEnabled: Boolean? = null,

    @CsvColumnMapping(name = "Uses Password and Has Logged In But Not in Over 1 Year", order = 25)
    @JsonProperty("usesPasswordAndHasLoggedInButNotInOverOneYear")
    var usesPasswordAndHasLoggedInButNotInOverOneYear: Boolean? = null,

    @CsvColumnMapping(name = "Uses Password and But Has Never Logged In", order = 26)
    @JsonProperty("usesPasswordAndHasNeverLoggedIn")
    var usesPasswordAndHasNeverLoggedIn: Boolean? = null,

    @CsvColumnMapping(name = "Years Since Last Password Change", order = 27)
    @JsonProperty("yearsSinceLastPasswordChange")
    var yearsSinceLastPasswordChange: Double? = null,

    @CsvColumnMapping(name = "Years Since Last Access Key Rotation", order = 28)
    @JsonProperty("yearsSinceLastAccessKeyRotation")
    var yearsSinceLastAccessKeyRotation: Double? = null,

    @CsvColumnMapping(name = "Years Since Access Key Last Used", order = 29)
    @JsonProperty("yearsSinceAccessKeyLastUsed")
    var yearsSinceAccessKeyLastUsed: Double? = null,

    @CsvColumnMapping(name = "Has Access Key That Has Never Been Used", order = 30)
    @JsonProperty("hasAccessKeyThatHasNeverBeenUsed")
    var hasAccessKeyThatHasNeverBeenUsed: Boolean = false,


    ) {
    init {
        activeUser = passwordEnabled||accessKey1Active||accessKey2Active||cert1Active||cert2Active
        usesPasswordAndHasNeverLoggedIn = passwordEnabled && passwordLastUsed == null
        usesPasswordButMFANotEnabled = passwordEnabled && !mfaActive
        hasAccessKeyThatHasNeverBeenUsed = (accessKey1Active && accessKey1LastUsedDate == null) || (accessKey2Active && accessKey2LastUsedDate == null)

        if(passwordEnabled) {
            if (passwordLastUsed != null) {
                yearsSinceLastLogin = ChronoUnit.DAYS.between(passwordLastUsed, LocalDateTime.now()) / 365.0
                usesPasswordAndHasLoggedInButNotInOverOneYear = yearsSinceLastLogin != null && yearsSinceLastLogin!! > 1.0
            }

            yearsSinceLastPasswordChange = if (passwordLastChanged != null) {
                ChronoUnit.DAYS.between(passwordLastChanged, LocalDateTime.now()) / 365.0
            } else {
                ChronoUnit.DAYS.between(userCreationTime, LocalDateTime.now()) / 365.0
            }
        }

        if(accessKey1Active) {
            if(accessKey1LastUsedDate != null) {
                val years = ChronoUnit.DAYS.between(accessKey1LastUsedDate,LocalDateTime.now())/365.0
                if(yearsSinceAccessKeyLastUsed == null || years>yearsSinceAccessKeyLastUsed!!) {
                    yearsSinceAccessKeyLastUsed = years
                }
            }

            if(accessKey1LastRotated != null) {
                val years = ChronoUnit.DAYS.between(accessKey1LastRotated,LocalDateTime.now())/365.0
                if(yearsSinceLastAccessKeyRotation == null || years>yearsSinceLastAccessKeyRotation!!) {
                    yearsSinceLastAccessKeyRotation=years
                }
            }

        }

        if(accessKey2Active) {
            if(accessKey2LastUsedDate != null) {
                val years = ChronoUnit.DAYS.between(accessKey2LastUsedDate,LocalDateTime.now())/365.0
                if(yearsSinceAccessKeyLastUsed == null || years>yearsSinceAccessKeyLastUsed!!) {
                    yearsSinceAccessKeyLastUsed = years
                }
            }

            if(accessKey2LastRotated != null) {
                val years = ChronoUnit.DAYS.between(accessKey2LastRotated,LocalDateTime.now())/365.0
                if(yearsSinceLastAccessKeyRotation == null || years>yearsSinceLastAccessKeyRotation!!) {
                    yearsSinceLastAccessKeyRotation=years
                }
            }
        }

    }
}

data class CredentialReportAnalysis(
    @CsvColumnMapping(name = "Audit Criteria", order = 1)
    @JsonProperty("auditCriteria")
    var auditCriteria: String = "",

    @CsvColumnMapping(name = "Affected Users", order = 2)
    @JsonProperty("affectedUsers")
    var affectedUsers: String = "",

    @CsvColumnMapping(name = "Percent", order = 3)
    @JsonProperty("percent")
    var percent: String = "",

    @CsvColumnMapping(name = "Minimum", order = 4)
    @JsonProperty("minimum")
    var minimum: Double? = null,

    @CsvColumnMapping(name = "Maximum", order = 4)
    @JsonProperty("maximum")
    var maximum: Double? = null

)


class CredentialReport : CliktCommand() {
    override fun help(context: com.github.ajalt.clikt.core.Context) = "Dumps key AWS resources"

    val inputOption by option("--input","-i",help = "Path to file credential report CSV")
    val downloadOption by option("--download","-d",help = "Download the latest credential report").flag()

    private val config by requireObject<VirtueAWSContext>()
    private val credentialReport = mutableListOf<IamCredentialReportEntry>()
    private val iamAnalysis = mutableListOf<CredentialReportAnalysis>()
    private val passwordUsersAnalysis = mutableListOf<CredentialReportAnalysis>()
    private val accessKeyUsersAnalysis = mutableListOf<CredentialReportAnalysis>()
    private val permissionAnalysis = mutableListOf<CredentialReportAnalysis>()

    init {
        this.installMordantMarkdown()
    }

    override fun run() {


        if(downloadOption){
            val client = config.getIamClient()
            runBlocking {
                downloadCredentialReport()
            }

        }
        else {
            val inputTemp = requireNotNull(inputOption) {"--input option required"}
            val input = Path(inputTemp)
            require(input.exists()) { "${input.absolutePathString()} does not exist." }

            credentialReport.addAll(
                DataSerializer.fromCsv(
                    Files.readString(input).replace("N/A", "").replace("no_information", ""),
                    IamCredentialReportEntry::class.java
                )
            )
            analyzeCredentialReport()
        }

    }

    suspend fun downloadCredentialReport() {

        val iamClient = config.getIamClient()
        try {
            // Step 1: Initiate the credential report generation
            println("Generating new credential report...")

            var generateReportResponse = iamClient.generateCredentialReport(GenerateCredentialReportRequest {})
            var loopCount = 0
            val delayMillis : Long = 5000
            val maxLoops = 15
            while(generateReportResponse.state==ReportStateType.Inprogress) {
                delay(delayMillis)
                config.prettyLogger.printlnInfo("Polling count $loopCount/$maxLoops...")
                generateReportResponse = iamClient.generateCredentialReport(GenerateCredentialReportRequest {})
                if(loopCount>maxLoops) {
                    config.prettyLogger.printlnError("Waited ${loopCount*delayMillis} iterations...")
                }
                loopCount++
            }
            if(generateReportResponse.state == ReportStateType.Complete) {
                val finalReportResponse = iamClient.getCredentialReport(GetCredentialReportRequest {})

                finalReportResponse.content?.let { reportContent ->
                    // The report content is Base64 encoded
                    val decodedReport = reportContent.decodeToString()
                    //val reportString = decodedReport.decodeToString()
                    config.prettyLogger.printlnSuccess(message=decodedReport)
                    // Save the report to a file
                    //val reportFile = File("aws_credential_report.csv")
                    //reportFile.writeText(reportString)
                    //println("Credential report successfully downloaded to ${reportFile.absolutePath}")
                    val downloadedCSVPath = config.toolDirectories.outputFile(ToolOutputDirectory.CREDENTIALREPORTDIR, ToolOutputFile.CREDENTIALREPORTDOWNLOADEDFILE,
                        ToolOutputExtension.CSV)
                    downloadedCSVPath?.writeText(decodedReport)
                    config.prettyLogger.printlnSuccess("Wrote to: $downloadedCSVPath")
                } ?: config.prettyLogger.printlnError("Credential report content is empty.")
            }
            else {
                config.prettyLogger.printlnError(title="Unable to get credential report","${generateReportResponse.state}: ${generateReportResponse.description}")
            }


        } catch (e: Exception) {
            println("An error occurred: ${e.message}")
            println("An error occurred: ${e.stackTraceToString()}")
        } finally {
            iamClient.close()
        }
    }

    fun analyzeCredentialReport() {


        val totalUsers = credentialReport.count()
        val activeUsers = credentialReport.count { it.activeUser }
        val usersUsingPasswords = credentialReport.count { it.passwordEnabled }
        val passwordUsersWithoutMfa = credentialReport.count { it.usesPasswordButMFANotEnabled ?: false }
        val passwordUsersHaventLoggedInOverYear = credentialReport.count { it.usesPasswordAndHasLoggedInButNotInOverOneYear ?: false}
        val passwordUsersHaveNeverLoggedIn = credentialReport.count {it.usesPasswordAndHasNeverLoggedIn ?: false}
        val usersUsingAccessKey = credentialReport.count {it.accessKey1Active||it.accessKey2Active}
        var minimumPasswordAgeOverOneYear : Double? = null
        var maximumPasswordAgeOverOneYear : Double? = null
        var passwordsOverOneYear : Int = 0

        val usersWithAccessKeysNeverUsed = credentialReport.count { it.hasAccessKeyThatHasNeverBeenUsed }

        var minimumAccessKeyUseAgeOverOneYear : Double? = null
        var maximumAccessKeyUseAgeOverOneYear : Double? = null
        var accessKeyUseAgeOverOneYear : Int = 0

        var minimumAccessKeyRotationAgeOverOneYear : Double? = null
        var maximumAccessKeyRotationAgeOverOneYear : Double? = null
        var accessKeyRotationAgeOverOneYear : Int = 0


        credentialReport.forEach {
            it.yearsSinceLastPasswordChange?.let { yearsSince ->
                if(yearsSince>1.0) {
                    passwordsOverOneYear++
                    if(minimumPasswordAgeOverOneYear==null || yearsSince < minimumPasswordAgeOverOneYear!!) {
                        minimumPasswordAgeOverOneYear = yearsSince
                    }

                    if(maximumPasswordAgeOverOneYear==null || yearsSince > maximumPasswordAgeOverOneYear!!) {
                        maximumPasswordAgeOverOneYear = yearsSince
                    }
                }
            }

            it.yearsSinceAccessKeyLastUsed?.let { yearsSince ->
                if(yearsSince>1.0) {
                    accessKeyUseAgeOverOneYear++
                    if(minimumAccessKeyUseAgeOverOneYear==null || yearsSince < minimumAccessKeyUseAgeOverOneYear!!) {
                        minimumAccessKeyUseAgeOverOneYear = yearsSince
                    }

                    if(maximumAccessKeyUseAgeOverOneYear==null || yearsSince > maximumAccessKeyUseAgeOverOneYear!!) {
                        maximumAccessKeyUseAgeOverOneYear = yearsSince
                    }
                }
            }

            it.yearsSinceLastAccessKeyRotation?.let { yearsSince ->
                if(yearsSince>1.0) {
                    accessKeyRotationAgeOverOneYear++
                    if(minimumAccessKeyRotationAgeOverOneYear==null || yearsSince < minimumAccessKeyRotationAgeOverOneYear!!) {
                        minimumAccessKeyRotationAgeOverOneYear = yearsSince
                    }

                    if(maximumAccessKeyRotationAgeOverOneYear==null || yearsSince > maximumAccessKeyRotationAgeOverOneYear!!) {
                        maximumAccessKeyRotationAgeOverOneYear = yearsSince
                    }
                }
            }


        }

        iamAnalysis.addAll(listOf(
            createAnalysisEntry("Total Users",totalUsers,totalUsers),
            createAnalysisEntry("Inactive Users",totalUsers-activeUsers,totalUsers),
            createAnalysisEntry("Active Users Using a Password",usersUsingPasswords,totalUsers),
            createAnalysisEntry("Active Users Using an Access Key",usersUsingAccessKey,totalUsers)
        ))
        passwordUsersAnalysis.addAll(listOf(
            createAnalysisEntry("Active Users Using a Password Without MFA",passwordUsersWithoutMfa,usersUsingPasswords),
            createAnalysisEntry("Active Users Using a Password That Haven't Logged In in Over a Year",passwordUsersHaventLoggedInOverYear,usersUsingPasswords),
            createAnalysisEntry("Active Users Using a Password That Have Never Logged In",passwordUsersHaveNeverLoggedIn,usersUsingPasswords),
            createAnalysisEntry("Active Users Using a Password Older Than One Year",passwordsOverOneYear,usersUsingPasswords, minimumPasswordAgeOverOneYear,maximumPasswordAgeOverOneYear),
        ))

        accessKeyUsersAnalysis.addAll(listOf(
            createAnalysisEntry("Active Users With Access Keys That Have Never Been Used",usersWithAccessKeysNeverUsed,usersUsingAccessKey),
            createAnalysisEntry("Active Users With Access Keys That Haven't Been Used in Over a Year",accessKeyUseAgeOverOneYear,usersUsingAccessKey,minimumPasswordAgeOverOneYear,maximumPasswordAgeOverOneYear),
            createAnalysisEntry("Active Users With Access Keys That Haven't Been Rotated in Over a Year",accessKeyRotationAgeOverOneYear,usersUsingAccessKey,minimumAccessKeyRotationAgeOverOneYear,maximumAccessKeyRotationAgeOverOneYear),
        ))

//        permissionAnalysis.addAll(listOf(
//
//        ))

//        iamAnalysis.forEach { entry ->
//            println("${entry.auditCriteria}: ${entry.affectedUsers} ${entry.percent} ${entry.minimum} ${entry.maximum}")
//
//        }

        val markdownOutput = buildString {
            appendLine("## IAM Users Analysis")
            appendLine(DataSerializer.toMarkdownTable(iamAnalysis))

            appendLine("## Active Password Enabled Users Analysis")
            appendLine(DataSerializer.toMarkdownTable(passwordUsersAnalysis))

            appendLine("## Active Access Keys Analysis")
            appendLine(DataSerializer.toMarkdownTable(accessKeyUsersAnalysis))
        }

        config.prettyLogger.printlnMarkdown(markdownOutput.toString())
        val mdoutputpath = config.toolDirectories.outputFile(ToolOutputDirectory.CREDENTIALREPORTDIR,ToolOutputFile.CREDENTIALREPORTANALYSISFILE,ToolOutputExtension.MD)
        mdoutputpath?.writeText(markdownOutput.toString())
        config.prettyLogger.printlnSuccess("Output written to: $mdoutputpath")

        val csvoutputpath = config.toolDirectories.outputFile(ToolOutputDirectory.CREDENTIALREPORTDIR,ToolOutputFile.CREDENTIALREPORTANALYSISFILE,ToolOutputExtension.CSV)
        csvoutputpath?.writeText(DataSerializer.toCsv(iamAnalysis))
        csvoutputpath?.appendText(DataSerializer.toCsv(passwordUsersAnalysis))
        csvoutputpath?.appendText(DataSerializer.toCsv(accessKeyUsersAnalysis))

        config.prettyLogger.printlnSuccess("Output written to: $csvoutputpath")

        val jsonoutputpath = config.toolDirectories.outputFile(ToolOutputDirectory.CREDENTIALREPORTDIR,ToolOutputFile.CREDENTIALREPORTANALYSISFILE,ToolOutputExtension.JSON)
        jsonoutputpath?.writeText(DataSerializer.toJson(iamAnalysis))
        jsonoutputpath?.appendText(DataSerializer.toJson(passwordUsersAnalysis))
        jsonoutputpath?.appendText(DataSerializer.toJson(accessKeyUsersAnalysis))
        config.prettyLogger.printlnSuccess("Output written to: $jsonoutputpath")

        val formats = listOf(ToolOutputExtension.CSV,ToolOutputExtension.JSON,ToolOutputExtension.MD)
        formats.forEach { format ->
            val thePath = config.toolDirectories.outputFile(ToolOutputDirectory.CREDENTIALREPORTDIR,ToolOutputFile.CREDENTIALREPORTFILE,format)
            when(format) {
                ToolOutputExtension.JSON -> thePath?.writeText(DataSerializer.toJson(credentialReport))
                ToolOutputExtension.CSV -> thePath?.writeText(DataSerializer.toCsv(credentialReport))
                ToolOutputExtension.MD -> thePath?.writeText(DataSerializer.toMarkdownTable(credentialReport))
                else -> {}
            }
            config.prettyLogger.printlnSuccess("Output written to: $thePath")
        }




    }

    fun getPercent(number: Int, outOf : Int) = "${round((100.0*number.toDouble()/outOf.toDouble())).toInt()}%"

    fun getCountOfTotalUsers(number: Int, outOf : Int) = "$number / $outOf"

    fun createAnalysisEntry(title : String,number : Int, total : Int, minimum : Double? = null, maximum : Double? = null) = CredentialReportAnalysis(title,getCountOfTotalUsers(number,total),getPercent(number,total),minimum,maximum)


}