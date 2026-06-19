# SmartFileKit

**SmartFileKit** is a **lightweight**, **high-performance**, and **security-focused** .NET library designed for **secure file validation**, **file signature (magic byte) verification**, **MIME type detection**, and **file classification**. Built with **reliability**, **performance**, and **zero external dependencies** in mind, it is ideal for **enterprise applications** and **secure file upload scenarios**.

[![NuGet Version](https://img.shields.io/nuget/v/SmartFileKit.svg?style=flat-square)](https://www.nuget.org/packages/SmartFileKit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

---

## 🚀 Key Features

- **File Size Formatting & Calculations:** Convert bytes dynamically to KB, MB, GB, and TB units, perform arithmetic operations and comparisons, and format output with configurable decimal precision using `CultureInfo.InvariantCulture`.
- **MIME & Category Detection:** Automatically identify MIME types and high-level categories (`Image`, `Document`, `Spreadsheet`, `Presentation`, `Archive`, `Video`, `Audio`, `Executable`, etc.) for over 40 popular file formats.
- **Content-Based Magic Bytes Verification:** Inspect leading header bytes (up to 4096 bytes) rather than relying solely on file extensions. This prevents extension-spoofing attacks (e.g., detecting `.exe` binaries disguised as `.jpg` or arbitrary ZIP packages renamed to `.docx`).
- **Filename Sanitization:** Clean user-supplied filenames by converting Turkish characters to their English equivalents, removing invalid filesystem chars, mitigating directory traversal attacks, and preventing Windows reserved device name collisions (`CON`, `PRN`, `NUL`, etc.).
- **Fluent Validation API:** A highly readable builder syntax for size ranges, allowed/blocked extensions, allowed/blocked MIME types, allowed/blocked categories, and active signature validation.
- **Advanced File Analysis & Security Engine:** Dynamically analyze files to generate detailed reports containing risk scores (0-100), risk levels, threat issue lists, Office file structure validation (refines ZIP to DOCX/XLSX/PPTX), ZIP archive inner executable scanning, polyglot file detection (multiple signatures), and Shannon Entropy calculations.
- **Zero-Dependency & Low-Allocation:** Completely self-contained library utilizing array and stream buffer pooling to maximize throughput in high-scale ASP.NET Core APIs.

---

## 📦 Installation

Install via the .NET CLI:

```bash
dotnet add package SmartFileKit
```

Or via the Package Manager Console:

```powershell
Install-Package SmartFileKit
```

---

## 🛠️ Usage Examples

### 1. File Size Formatting & Extensions

The `FileSize` struct supports comparison and arithmetic operators, and decimal formatting is culture-invariant (always uses a dot `.`).

```csharp
using SmartFileKit;
using SmartFileKit.Domain;

// Define sizes fluently
FileSize maxLimit = 5.MB();
FileSize minLimit = 500.KB();

// Alternative static creation methods
FileSize size1 = FileSize.FromBytes(2048);
FileSize size2 = FileSize.FromKilobytes(1.5);
FileSize size3 = FileSize.FromMegabytes(10);
FileSize size4 = FileSize.FromGigabytes(2.5);
FileSize size5 = FileSize.FromTerabytes(1);

// Convert numeric types to FileSize
long bytesCount = 1048576 * 3; // 3 MB
FileSize size = bytesCount.ToFileSize();

Console.WriteLine(size.ToString());    // Output: "3.00 MB" (Default precision is 2)
Console.WriteLine(size.ToString(1));   // Output: "3.0 MB"

// Comparisons and arithmetic (full support for +, -, *, /, <, >, <=, >=, ==, !=)
if (size < maxLimit)
{
    FileSize totalSpace = size + 10.MB();
    FileSize scaled = minLimit * 3;
    FileSize halved = maxLimit / 2;
    Console.WriteLine($"Total Space: {totalSpace}"); // Output: "13.00 MB"
}
```

### 2. Filename Sanitization & Directory Traversal Protection

Normalize names before saving them to disk. This converts special characters, strips path manipulation tricks, and avoids reserving OS filenames.

```csharp
using SmartFileKit;

// Turkish character normalization
string fileName1 = FileName.Sanitize("özel rapor (2026).pdf");
// Output: "ozel rapor (2026).pdf"

// Directory traversal protection
string fileName2 = FileName.Sanitize("../../../etc/passwd");
// Output: "etc_passwd"

string fileName3 = FileName.Sanitize("..\\..\\windows\\system32.dll");
// Output: "windows_system32.dll"

// Windows Reserved name resolution
string fileName4 = FileName.Sanitize("CON.txt");
// Output: "_CON.txt"
```

### 3. MIME and Category Detection

Detect the true file format using `Stream`, `byte[]`, or `string` file paths. Seekable streams are automatically rewound back to their original position after signature inspection.

```csharp
using System.IO;
using SmartFileKit;
using SmartFileKit.Domain;
using SmartFileKit.Detection;

// Detection from Stream
using (var stream = File.OpenRead("upload.dat"))
{
    FileFormatInfo format = FileType.GetFormat(stream);
    
    if (format != null)
    {
        Console.WriteLine($"Extension: {format.Extension}"); // e.g. ".jpg"
        Console.WriteLine($"MIME:      {format.MimeType}");  // e.g. "image/jpeg"
        Console.WriteLine($"Category:  {format.Category}");  // e.g. "Image"
    }

    // Direct helper checks (also support byte[] and file path)
    bool isImage = FileType.IsImage(stream);
    bool isArchive = FileType.IsArchive(stream);
}

// Detection from file path or byte array
FileFormatInfo formatFromPath = FileType.GetFormat("C:\\uploads\\document.pdf");
bool isDoc = FileType.IsDocument(new byte[] { 0x25, 0x50, 0x44, 0x46 }); // PDF signature
bool isVideo = FileType.IsVideo("C:\\uploads\\video.mp4"); // filepath

// Available categories in FileCategory enum:
// Unknown, Image, Document, Spreadsheet, Presentation, Archive, Audio, Video, Executable, Web, Data

// Dynamic MIME/Category Mapping Lookup using MimeMapper
string mime = MimeMapper.GetMimeType(".jpg");       // "image/jpeg"
string ext = MimeMapper.GetExtension("image/png");   // ".png"
FileCategory cat1 = MimeMapper.GetCategory(".pdf"); // FileCategory.Document
FileCategory cat2 = MimeMapper.GetCategoryByMimeType("application/zip"); // FileCategory.Archive
```

### 4. Fluent File Validation

Enforce security and constraints during file uploads. Spoofing checks are active by default to compare extension declarations against actual headers.

```csharp
using System;
using SmartFileKit.Validation;
using SmartFileKit.Domain;

byte[] fileData = new byte[] { 0x00, 0x00, 0x00, 0x00 }; // E.g., user upload

// Validate can accept: Stream, byte[], string file path, or FileInfo
var result = FileValidator.Validate(fileData, "avatar.jpg")
    .MaxSize(5.MB())
    .MinSize(10.KB())
    .AllowedExtensions(".jpg", ".png")
    .BlockedExtensions(".gif")
    .AllowedMimeTypes("image/jpeg", "image/png")
    .BlockedMimeTypes("image/gif")
    .AllowedCategories(FileCategory.Image)
    .BlockedCategories(FileCategory.Executable)
    .VerifySignature(true) // Verify magic bytes (default: true)
    .AllowEmpty(false)     // Allow empty files (default: false)
    .Execute();

if (!result.IsValid)
{
    Console.WriteLine("Validation Failed!");
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"- {error}");
    }
}

// Or throw a FileValidationException directly:
try
{
    FileValidator.Validate(fileData, "avatar.jpg")
        .MaxSize(5.MB())
        .AllowedExtensions(".jpg")
        .ThrowIfInvalid();
}
catch (FileValidationException ex)
{
    Console.WriteLine(ex.Message);
}
```

### 5. Reusable Upload Security Policies

Define standard security policies thread-safely once and validate different file streams against them.

```csharp
using System.IO;
using SmartFileKit.Security;
using SmartFileKit.Domain;
using SmartFileKit.Validation;

// Define a reusable security policy
public static class SecurityPolicies
{
    public static readonly UploadPolicy WebImagePolicy = UploadPolicy.Create()
        .MaxSize(10.MB())
        .AllowImages() // Pre-defined helper: PNG, JPG, JPEG, GIF, WEBP, BMP, SVG
        .BlockExtensions(".exe", ".dll", ".bat") // Extra safety
        .EnforceSignature(true); // Verify binary signature (magic bytes)
}

// Validate uploads against the policy in controllers / handlers
using (var stream = File.OpenRead("user_avatar.png"))
{
    FileValidationResult result = SecurityPolicies.WebImagePolicy.Validate(stream, "user_avatar.png");
    if (!result.IsValid)
    {
        Console.WriteLine("Upload policy violated!");
    }
}
```

### 6. Advanced File Analysis & Security Engine

Analyze uploaded files dynamically to perform signature checks, structural checks on ZIP/Office files, polyglot detection, entropy calculation, and generate a security risk score.

```csharp
using System.IO;
using SmartFileKit.Analysis;
using SmartFileKit.Domain;

// Simple analysis
using (var stream = File.OpenRead("invoice.pdf"))
{
    FileAnalysisReport report = FileAnalyzer.Analyze(stream, "invoice.pdf");
    
    Console.WriteLine($"Is Safe:      {report.IsSafe}");
    Console.WriteLine($"Is Suspicious: {report.IsSuspicious}");
    Console.WriteLine($"Risk Score:    {report.RiskScore} / 100");
    Console.WriteLine($"Risk Level:    {report.RiskLevel}");
    Console.WriteLine($"Actual Type:   {report.ActualFileType}"); // e.g. "pdf"
    
    foreach (var issue in report.Issues)
    {
        Console.WriteLine($"- Warning: {issue.Type} - {issue.Description} ({issue.Severity})");
    }
}

// Advanced fluent configuration
using (var stream = File.OpenRead("uploaded.dat"))
{
    FileAnalysisReport report = FileAnalyzer.Create()
        .ValidateSignature(true)
        .ValidateMime(true)
        .ValidateStructure(true)
        .CalculateRiskScore(true)
        .CheckEntropy(true, threshold: 7.5)
        .Analyze(stream, "data.txt", "text/plain");

    if (report.IsSuspicious)
    {
        Console.WriteLine($"Suspicious file detected! Entropy: {report.Entropy}");
    }
}
```

### 7. Cryptographic Hashing & Duplicate Detection

#### Cryptographic Hashing
Generate hashes for streams and byte arrays with low-overhead algorithms.

```csharp
using System.IO;
using SmartFileKit.Security;

// Hashing streams (MD5, SHA1, SHA256, SHA512)
using (var stream = File.OpenRead("document.pdf"))
{
    string sha256 = FileHash.Sha256(stream);
    string md5 = FileHash.Calculate(stream, HashAlgorithmType.MD5);
}
```

#### File Fingerprinting
Combine physical and semantic characteristics into a single `FileFingerprint` for unified identification.

```csharp
using System.IO;
using SmartFileKit.Security;

using (var stream = File.OpenRead("document.pdf"))
{
    FileFingerprint fingerprint = FileFingerprint.Generate(stream, "document.pdf");
    
    Console.WriteLine($"Size:           {fingerprint.Size} bytes");
    Console.WriteLine($"SHA256:         {fingerprint.Sha256}");
    Console.WriteLine($"MIME Type:      {fingerprint.MimeType}");
    Console.WriteLine($"Signature Type: {fingerprint.SignatureType}"); // e.g. "pdf"
    Console.WriteLine($"Category:       {fingerprint.Category}");      // e.g. Document
}
```

#### Duplicate Detection
Compare files byte-by-byte or via pre-calculated fingerprints and hashes.

```csharp
using System.IO;
using SmartFileKit.Security;

using (var s1 = File.OpenRead("file1.dat"))
using (var s2 = File.OpenRead("file2.dat"))
{
    // Fast, byte-by-byte comparison of streams (resets positions automatically)
    bool isDuplicateStream = DuplicateDetector.AreSame(s1, s2);
    
    // Compare via pre-computed fingerprints
    var fp1 = FileFingerprint.Generate(s1);
    var fp2 = FileFingerprint.Generate(s2);
    bool isDuplicateFingerprint = DuplicateDetector.AreSame(fp1, fp2);
    
    // Hash string comparison helper
    bool isDuplicateHash = DuplicateDetector.Compare(fp1.Sha256, fp2.Sha256);
}
```

### 8. File Name Risk & Security Analysis

Conduct extension validation, double extension checking, and filename safety scans (traversals, reserved words, shell chars).

```csharp
using SmartFileKit.Security;

// Dangerous extension check
bool isDangerous = FileSecurity.IsDangerousExtension("setup.exe"); // true

// Double extension verification (invoice.pdf.exe)
DoubleExtensionResult doubleExt = FileSecurity.HasDoubleExtension("invoice.pdf.exe");
if (doubleExt.HasDoubleExtension)
{
    Console.WriteLine($"Disguised extension: {doubleExt.SecondExtension} (Dangerous: {doubleExt.IsDangerous})");
}

// Filename risk scan
FileNameAnalysisResult riskReport = FileSecurity.AnalyzeFileName("../CON.txt");
if (!riskReport.IsSafe)
{
    Console.WriteLine($"Threat Score: {riskReport.RiskScore} / 100");
    foreach (var issue in riskReport.Issues)
    {
        Console.WriteLine($"- {issue}");
    }
}
```

### 9. Image & Office Metadata Readers

Extract metadata from images and Office files without external dependencies.

```csharp
using SmartFileKit.Security;

// Image dimensions (zero dependency)
using (var stream = File.OpenRead("photo.jpg"))
{
    ImageMetadataResult meta = ImageMetadata.Read(stream);
    if (meta.IsValid)
    {
        Console.WriteLine($"Image: {meta.Width}x{meta.Height} ({meta.Format})");
    }
}

// Office properties (author, title, creation, company)
using (var stream = File.OpenRead("proposal.docx"))
{
    OfficeMetadataResult meta = OfficeMetadata.Read(stream);
    if (meta.IsValid)
    {
        Console.WriteLine($"Author: {meta.Author}, Company: {meta.Company}");
    }
}
```

---

## 🛡️ Security Best Practices

1. **Never Trust Extensions:** Users can easily rename a malicious `.exe` file to `.jpg`. SmartFileKit inspects binary headers (`VerifySignature` option) to determine the true file format. Always validate signatures in production.
2. **Sanitize Output Names:** Do not use the original `FileName` header directly when writing uploads to disk. Always execute `FileName.Sanitize` to protect against path traversal attacks.

---

## ⚡ Performance Optimization

- **Fast Header Scanning:** The signature engine scans only the first **4096 bytes** of a file, keeping execution times under milliseconds even for multi-gigabyte uploads.
- **Rewindable Streams:** If the input `Stream` supports seeking, its pointer is reset to the starting position when detection concludes. This ensures consecutive writes or downstream handlers receive the stream intact.

---

## 📄 License

This project is licensed under the **MIT License**.