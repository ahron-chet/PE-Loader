<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>

<h1>PE Loader Project</h1>

<p>This project is a manual Portable Executable (PE) loader, designed to read a PE file, allocate memory for it, and execute it in memory. It's implemented in C++.</p>

<h2>Features</h2>
<ul>
    <li>Reads the PE file into memory.</li>
    <li>Allocates necessary memory for the PE file execution.</li>
    <li>Maps the sections of the PE to the allocated memory.</li>
    <li>Performs base relocations.</li>
    <li>Fixes the Import Address Table (IAT).</li>
    <li>Executes the loaded PE file from memory.</li>
</ul>

<h2>Usage</h2>
<p>Make sure you have the required dependencies installed and simply run the project. The loader will take care of reading, mapping, and executing the PE.</p>

<code>
 PE-Loader.exe pathTo.exe
</code>


<h2>Issues & Contribution</h2>
<p>If you encounter any issues or would like to contribute to the project, please open a pull request or issue on the project's repository.</p>

</body>
</html>
