package com.nickcoblentz.aws.models


import java.nio.file.Path
import kotlin.io.path.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.createDirectories
import kotlin.io.path.exists


enum class ToolOutputDirectory(val value: String) {
   BASE("Base"),
    CREDENTIALREPORTDIR("CredentialReport"),
    IAMDIR("iam")
}

enum class ToolInputDirectory(val value: String) {
    BASEDIR("Base")
}

enum class ToolOutputFile(val value: String) {
    CREDENTIALREPORTFILE("CredentialReport"),
    CREDENTIALREPORTDOWNLOADEDFILE("CredentialReportDownloaded"),
    CREDENTIALREPORTANALYSISFILE("CredentialReportAnalysis"),
    IAMSUMMARY("IamSummary"),
    IAMUSERS("IamUsers"),
    IAMPOLICIES("IamPolicies")
}

enum class ToolOutputExtension(val value: String) {
    CSV(".csv"),
    MD(".md"),
    JSON(".json"),
    NONE("")
}

class ToolDirectories(val inputBaseDirectory: Path, val outputBaseDirectory: Path) {
    private val toolOutputDirectories = mutableMapOf<ToolOutputDirectory, Path>()
    private val toolInputDirectories  = mutableMapOf<ToolInputDirectory,Path>()
    private var outputDirectoriesProcessed = false
    init {
        require(inputBaseDirectory.exists()) { "Input base directory ${inputBaseDirectory.absolutePathString()} does not exist"}
        toolOutputDirectories[ToolOutputDirectory.BASE] = outputBaseDirectory
        toolInputDirectories[ToolInputDirectory.BASEDIR] = inputBaseDirectory
        ensureOutputDirectoriesCreated()
    }

    fun withNewOutputDirectory(newDirectory: ToolOutputDirectory, parentDirectory : ToolOutputDirectory = ToolOutputDirectory.BASE) {
        toolOutputDirectories[newDirectory] = Path(toolOutputDirectories[parentDirectory]!!.absolutePathString(), newDirectory.value)
    }

    fun withNewInputDirectory(newDirectory: ToolInputDirectory, parentDirectory : ToolInputDirectory = ToolInputDirectory.BASEDIR) {
        toolInputDirectories[newDirectory] = Path(toolInputDirectories[parentDirectory]!!.absolutePathString(), newDirectory.value)
    }

    fun ensureOutputDirectoriesCreated() {
        toolOutputDirectories.values.forEach { it.createDirectories() }
        outputDirectoriesProcessed = true
    }

    fun outputDirectory(directory: ToolOutputDirectory) : Path? {
        require(outputDirectoriesProcessed) {"Output directories must be created before accessing"}
        require(toolOutputDirectories.containsKey(directory)) {"Output directory $directory does not exist"}
        if(toolOutputDirectories.keys.contains(directory))
            return toolOutputDirectories[directory]
        return null
    }

    fun inputDirectory(directory: ToolInputDirectory) = toolInputDirectories[directory]!!

    fun outputFile(directory: ToolOutputDirectory, filename : ToolOutputFile, extension : ToolOutputExtension= ToolOutputExtension.NONE) : Path? {
        outputDirectory(directory)?.let {
            return Path(it.absolutePathString(), filename.value+extension.value)
        }
        return null
    }

    fun inputFile(directory : ToolInputDirectory, filename : String) = Path(inputDirectory(directory).absolutePathString(), filename)

}

