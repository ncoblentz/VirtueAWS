package com.nickcoblentz.kubepentest.utils

import com.github.ajalt.mordant.markdown.Markdown
import com.github.ajalt.mordant.rendering.TextColors
import com.github.ajalt.mordant.rendering.TextStyles
import com.github.ajalt.mordant.terminal.Terminal


/**
 * Utility class for formatted logging with color support.
 */
class PrettyLogger {
    private val terminal: Terminal = Terminal(width = 200)

    var verbose = true

    /**
     * Print a colored message with optional title.
     */
    fun printlnColor(title: String = "", message: String = "", textColor: TextColors = TextColors.white, stderr: Boolean = false) {
        if (title.isNotBlank())
            terminal.print("${(TextStyles.bold + textColor)(title)} ", stderr = stderr)
        if (message.isNotBlank())
            terminal.print("${(TextStyles.reset + textColor)(message)} ", stderr = stderr)
        terminal.println(stderr = stderr)
    }

    /**
     * Print markdown formatted text.
     */
    fun printlnMarkdown(markdown: String) {
        terminal.println(Markdown(markdown = markdown))
    }

    /**
     * Helper function to print a message with a specific color if a condition is met.
     */
    private fun printIfCondition(
        condition: Boolean, 
        title: String = "", 
        message: String = "", 
        textColor: TextColors, 
        stderr: Boolean = false
    ) {
        if (condition) {
            printlnColor(title, message, textColor, stderr)
        }
    }

    /**
     * Print an error message.
     */
    fun printlnError(title: String = "", message: String = "") {
        printlnColor(title, message, TextColors.brightRed, true)
    }

    /**
     * Print an informational message (only if verbose is enabled).
     */
    fun printlnInfo(title: String = "", message: String = "") {
        printIfCondition(verbose, title, message, TextColors.white)
    }

    /**
     * Print a success message.
     */
    fun printlnSuccess(title: String = "", message: String = "") {
        printlnColor(title, message, TextColors.brightGreen)
    }

    /**
     * Print a warning message (only if verbose is enabled).
     */
    fun printlnWarning(title: String = "", message: String = "") {
        printIfCondition(verbose, title, message, TextColors.yellow)
    }
}


/**
 * Log a success message with a path
 */
fun PrettyLogger.logSuccess(message: String, path: java.nio.file.Path) {
    printlnSuccess(message = "$message ${path.toAbsolutePath()}")
}

/**
 * Log an error with exception details
 */
fun PrettyLogger.logError(message: String, exception: Throwable) {
    printlnError(message = "$message: ${exception.message}")
}
