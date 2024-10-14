package me.markoutte.joker.parse_html.step2

import me.markoutte.joker.helpers.ComputeClassWriter
import me.markoutte.joker.parse_html.step1.asByteArray
import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.Options
import org.objectweb.asm.*
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.net.URLClassLoader
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit
import kotlin.io.path.writeBytes
import kotlin.random.Random

@ExperimentalStdlibApi
fun main(args: Array<String>) {
    val options = Options().apply {
        addOption("c", "class", true, "Java class fully qualified name")
        addOption("m", "method", true, "Method to be tested")
        addOption("cp", "classpath", true, "Classpath with libraries")
        addOption("t", "timeout", true, "Maximum time for fuzzing in seconds")
        addOption("s", "seed", true, "The source of randomness")
    }
    val parser = DefaultParser().parse(options, args)
    val className = parser.getOptionValue("class")
    val methodName = parser.getOptionValue("method")
    val classPath = parser.getOptionValue("classpath")
    val timeout = parser.getOptionValue("timeout")?.toLong() ?: 120L
    val seed = parser.getOptionValue("seed")?.toInt() ?: Random.nextInt()
    val random = Random(seed)

    println("Running: $className.$methodName) with seed = $seed")
    val errors = mutableSetOf<String>()
    val b = ByteArray(300)
    val start = System.nanoTime()

    val javaMethod = try {
        loadJavaMethod(className, methodName, classPath)
    } catch (t: Throwable) {
        println("Method $className#$methodName is not found")
        return
    }

    val seeds = mutableMapOf<Int, ByteArray>(
        -1 to """<!DOCTYPE html><html><body><h1>Hello, Egor!</h1></body></html>""".asByteArray(b.size)!!,
        -2 to """<html><body><title>Homework!</title></body></html>""".asByteArray(b.size)!!,
        -3 to """<html><div></span> I'm wrong </div></span></html>""".asByteArray(b.size)!!
    )

    while(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(timeout)) {
        val buffer = seeds.values.randomOrNull(random)?.let(Random::mutate)
            ?: b.apply(random::nextBytes)
        val inputValues = generateInputValues(javaMethod, buffer)
        val inputValuesString = "${javaMethod.name}: ${inputValues.contentDeepToString()}"
        try {
            ExecutionPath.id = 0
            javaMethod.invoke(null, *inputValues).apply {
                val seedId = ExecutionPath.id
                if (seeds.putIfAbsent(seedId, buffer) == null) {
                    println("New seed added: ${seedId.toHexString()}")
                }
            }
        } catch (e: InvocationTargetException) {
            if (errors.add(e.targetException::class.qualifiedName!!)) {
                val errorName = e.targetException::class.simpleName
                println("New error found: $errorName")
                val path = Paths.get("report$errorName.txt")
                Files.write(path, listOf(
                    "${e.targetException.stackTraceToString()}\n",
                    "$inputValuesString\n",
                    "${buffer.contentToString()}\n",
                ))
                Files.write(path, buffer, StandardOpenOption.APPEND)
                println("Saved to: ${path.fileName}")
            }
        }
    }

    println("Seeds found: ${seeds.size}")
    println("Errors found: ${errors.size}")
    println("Time elapsed: ${TimeUnit.NANOSECONDS.toMillis(
        System.nanoTime() - start
    )} ms")
}

fun loadJavaMethod(className: String, methodName: String, classPath: String): Method {
    val libraries = classPath
        .split(File.pathSeparatorChar)
        .map { File(it).toURI().toURL() }
        .toTypedArray()
    val classLoader = object : URLClassLoader(libraries) {
        override fun loadClass(name: String, resolve: Boolean): Class<*> {
            return if (name.startsWith(className.substringBeforeLast('.'))) {
                transformAndGetClass(name).apply {
                    if (resolve) resolveClass(this)
                }
            } else {
                super.loadClass(name, resolve)
            }
        }
        fun transformAndGetClass(name: String): Class<*> {
            val owner = name.replace('.', '/')
            var bytes =
                getResourceAsStream("$owner.class")!!.use { it.readBytes() }
            val reader = ClassReader(bytes)
            val cl = this
            val writer = ComputeClassWriter(
                reader, ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES, cl
            )
            val transformer = object : ClassVisitor(Opcodes.ASM9, writer) {
                override fun visitMethod(
                    access: Int,
                    name: String?,
                    descriptor: String?,
                    signature: String?,
                    exceptions: Array<out String>?
                ): MethodVisitor {
                    return object : MethodVisitor(
                        Opcodes.ASM9,
                        super.visitMethod(
                            access, name, descriptor, signature, exceptions
                        )
                    ) {
                        val ownerName =
                            ExecutionPath.javaClass.canonicalName.replace('.', '/')
                        val fieldName = "id"

                        override fun visitLineNumber(line: Int, start: Label?) {
                            visitFieldInsn(
                                Opcodes.GETSTATIC, ownerName, fieldName, "I"
                            )
                            visitLdcInsn(line)
                            visitInsn(Opcodes.IADD)
                            visitFieldInsn(
                                Opcodes.PUTSTATIC, ownerName, fieldName, "I"
                            )
                            super.visitLineNumber(line, start)
                        }
                    }
                }
            }
            reader.accept(transformer, ClassReader.SKIP_FRAMES)
            bytes = writer.toByteArray().also {
                if (name == className) {
                    Paths.get("Instrumented.class").writeBytes(it)
                }
            }
            return defineClass(name, bytes, 0, bytes.size)
        }
    }
    val javaClass = classLoader.loadClass(className)
    val javaMethod = javaClass.declaredMethods.first {
        "${it.name}(${it.parameterTypes.joinToString(",") {
                c -> c.typeName
        }})" == methodName
    }
    return javaMethod
}

fun getQueryHTML(buffer: ByteBuffer): String {
    val open_tags = listOf("div", "p", "span", "a", "h1", "img", "br", "li", "table",)
    val close_tags = listOf("/div", "/p", "/span", "/a", "/h1", "/img", "/br", "/li", "/table")
    val alphabet = ('A'..'Z') + ('a'..'z') + ('0'..'9')
    val len = buffer.get().toUByte().toInt() % 100

    val isCorrect = (buffer.get().toUByte().toInt() % 10) == 0
    val stack = mutableListOf<String>()
    val query = StringBuilder()

    for (i in 1..len) {
        val action = buffer.get().toUByte().toInt() % 3
        when (action) {
            0 -> {
                val tag = open_tags.random(buffer.asRandom())
                query.append("<$tag>")
                if (isCorrect) {
                    stack.add("/$tag")
                }
            }
            1 -> {
                if (isCorrect) {
                    if (stack.size > 0) {
                        val tag = stack.removeLast()
                        query.append("<$tag>")
                    } else {
                        val tag = open_tags.random(buffer.asRandom())
                        query.append("<$tag>")
                        stack.add("/$tag")
                    }
                } else {
                    val tag = close_tags.random(buffer.asRandom())
                    query.append("<$tag>")
                }

            }
            2 -> {
                val textLength =
                    buffer.get().toUByte().toInt() % 30
                repeat(textLength) {
                    query.append(alphabet.random(buffer.asRandom()))
                }
            }
        }
    }
    while (stack.size > 0) {
        val tag = stack.removeLast()
        query.append("<$tag>")
    }
    return query.toString()
}

fun ByteBuffer.asRandom(): Random {
    return Random(this.get().toUByte().toInt())
}

fun generateInputValues(method: Method, data: ByteArray): Array<Any> {
    val buffer = ByteBuffer.wrap(data)
    val parameterTypes = method.parameterTypes
    return Array(parameterTypes.size) {
        when (parameterTypes[it]) {
            Int::class.java -> buffer.get().toInt()
            IntArray::class.java -> IntArray(buffer.get().toUByte().toInt()) {
                buffer.get().toInt()
            }
            String::class.java -> getQueryHTML(buffer)
            else -> error("Cannot create value of type ${parameterTypes[it]}")
        }
    }
}

object ExecutionPath {
    @JvmField
    var id: Int = 0
}

fun Random.mutate(buffer: ByteArray): ByteArray {
    val operation = nextInt(4)
    return when (operation) {
        0 -> insertByte(buffer)
        1 -> deleteByte(buffer)
        2 -> swapBytes(buffer)
        3 -> randomizeByte(buffer)
        else -> buffer
    }
}

fun Random.insertByte(buffer: ByteArray): ByteArray {
    val pos = nextInt(buffer.size + 1)
    val newByte = nextInt(256).toByte()
    return buffer.copyOfRange(0, pos) + byteArrayOf(newByte) + buffer.copyOfRange(pos, buffer.size)
}

fun Random.deleteByte(buffer: ByteArray): ByteArray {
    if (buffer.isEmpty()) return buffer
    val pos = nextInt(buffer.size)
    return buffer.copyOfRange(0, pos) + buffer.copyOfRange(pos + 1, buffer.size)
}

fun Random.swapBytes(buffer: ByteArray): ByteArray {
    if (buffer.size < 2) {
        return buffer.copyOf()
    }
    val pos1 = nextInt(buffer.size)
    var pos2 = nextInt(buffer.size)
    while (pos1 == pos2) {
        pos2 = nextInt(buffer.size)
    }
    val tmp = buffer[pos1]
    buffer[pos1] = buffer[pos2]
    buffer[pos2] = tmp
    return buffer.copyOf()
}

fun Random.randomizeByte(buffer: ByteArray): ByteArray {
    val pos = nextInt(buffer.size)
    buffer[pos] = nextInt(256).toByte()
    return buffer.copyOf()
}
