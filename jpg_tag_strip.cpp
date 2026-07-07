// SPDX-License-Identifier: MIT
// Copyright (c) github.com/vblendpd

#include <filesystem>
#include <fstream>
#include <iostream>

const uint8_t* FindBytes(const uint8_t* haystack, size_t hlen, const uint8_t* needle, size_t nlen) {
  if (nlen == 0 || hlen < nlen)
    return nullptr;
  for (size_t i = 0; i + nlen <= hlen; i++) {
    if (std::memcmp(haystack + i, needle, nlen) == 0)
      return haystack + i;
  }
  return nullptr;
}

uint16_t Read16(const uint8_t* p, bool be) {
  return be ? static_cast<uint16_t>(p[0]) << 8 | p[1] : static_cast<uint16_t>(p[1]) << 8 | p[0];
}

uint32_t Read32(const uint8_t* p, bool be) {
  return be
           ? static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 | static_cast<uint32_t>(p[2]) << 8 | p[3]
           : static_cast<uint32_t>(p[3]) << 24 | static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[1]) << 8 | p[0];
}

void Wipe(uint8_t* p, uint32_t count) {
  if (count == 0)
    return;
  std::memset(p, ' ', count);
  p[count - 1] = 0;
}

enum class IFDKind { IFD0, ExifSub, GPS };

int64_t ProcessIFD(uint8_t* tiffBase, size_t tiffSize, uint32_t ifdOffset, bool be, IFDKind kind, int& editsMade, int64_t& gpsIFDOffsetOut) {
  if (ifdOffset + 2 > tiffSize)
    return -1;
  const uint16_t numEntries = Read16(tiffBase + ifdOffset, be);
  int64_t exifSubIFDOffset  = -1;
  const bool isIFD0         = kind == IFDKind::IFD0;
  const bool isGPS          = kind == IFDKind::GPS;

  for (uint16_t i = 0; i < numEntries; ++i) {
    const size_t entryOff = ifdOffset + 2 + static_cast<size_t>(i) * 12;
    if (entryOff + 12 > tiffSize)
      break;

    uint8_t* entry       = tiffBase + entryOff;
    const uint16_t tag   = Read16(entry, be);
    const uint16_t type  = Read16(entry + 2, be);
    const uint32_t count = Read32(entry + 4, be);

    const bool isTargetDateOrSoftware = (isIFD0 && (tag == 0x0131 || tag == 0x0132)) ||
      (kind == IFDKind::ExifSub && (tag == 0x9003 || tag == 0x9004)) ||
      (isGPS && tag == 0x001D);

    if (isTargetDateOrSoftware && type == 2) {
      const uint32_t typeSize = 1;
      const uint32_t dataSize = typeSize * count;
      uint8_t* dataPtr;
      if (dataSize <= 4) {
        dataPtr = entry + 8;
      }
      else {
        const uint32_t dataOffset = Read32(entry + 8, be);
        if (dataOffset + dataSize > tiffSize)
          continue;
        dataPtr = tiffBase + dataOffset;
      }
      Wipe(dataPtr, count);
      ++editsMade;
    }

    if (isIFD0 && tag == 0x8769 && type == 4) {
      exifSubIFDOffset = Read32(entry + 8, be);
    }
    if (isIFD0 && tag == 0x8825 && type == 4) {
      gpsIFDOffsetOut = Read32(entry + 8, be);
    }
  }
  return exifSubIFDOffset;
}

int ProcessExifPayload(uint8_t* tiff, size_t tiffSize) {
  if (tiffSize < 8)
    return 0;
  bool be;
  if (tiff[0] == 'M' && tiff[1] == 'M')
    be = true;
  else if (tiff[0] == 'I' && tiff[1] == 'I')
    be = false;
  else
    return 0;

  const uint16_t magic = Read16(tiff + 2, be);
  if (magic != 0x002A)
    return 0;

  uint32_t ifd0Offset  = Read32(tiff + 4, be);
  int editsMade        = 0;
  int64_t gpsIFDOffset = -1;

  int64_t exifSubIFDOffset = ProcessIFD(tiff, tiffSize, ifd0Offset, be, IFDKind::IFD0, editsMade, gpsIFDOffset);

  if (exifSubIFDOffset >= 0 && static_cast<size_t>(exifSubIFDOffset) < tiffSize) {
    int64_t dummy = -1;
    ProcessIFD(tiff, tiffSize, static_cast<uint32_t>(exifSubIFDOffset), be, IFDKind::ExifSub, editsMade, dummy);
  }
  if (gpsIFDOffset >= 0 && static_cast<size_t>(gpsIFDOffset) < tiffSize) {
    int64_t dummy = -1;
    ProcessIFD(tiff, tiffSize, static_cast<uint32_t>(gpsIFDOffset), be, IFDKind::GPS, editsMade, dummy);
  }
  return editsMade;
}

const char* XmpDateSoftwareProps[] = {
  "exif:DateTimeOriginal",
  "exif:DateTimeDigitized",
  "xmp:CreateDate",
  "xmp:ModifyDate",
  "xmp:MetadataDate",
  "photoshop:DateCreated",
  "tiff:DateTime",
  "xmp:CreatorTool",
};

int WipeXmpElementValue(uint8_t* buf, size_t len, const char* propName) {
  int edits            = 0;
  std::string openTag  = std::string("<") + propName + ">";
  std::string closeTag = std::string("</") + propName + ">";
  size_t searchFrom    = 0;
  while (searchFrom < len) {
    const uint8_t* found = FindBytes(buf + searchFrom, len - searchFrom, reinterpret_cast<const uint8_t*>(openTag.data()), openTag.size());
    if (!found)
      break;
    size_t contentStart = (found - buf) + openTag.size();
    if (contentStart >= len)
      break;

    const uint8_t* closeFound = FindBytes(buf + contentStart, len - contentStart, reinterpret_cast<const uint8_t*>(closeTag.data()), closeTag.size());
    if (!closeFound)
      break;
    const size_t contentEnd = closeFound - buf;
    if (contentEnd > contentStart) {
      std::memset(buf + contentStart, ' ', contentEnd - contentStart);
      ++edits;
    }
    searchFrom = contentEnd + closeTag.size();
  }
  return edits;
}

int WipeXmpAttributeValue(uint8_t* buf, size_t len, const char* propName) {
  int edits          = 0;
  std::string prefix = std::string(propName) + "=\"";
  size_t searchFrom  = 0;
  while (searchFrom < len) {
    const uint8_t* found = FindBytes(buf + searchFrom, len - searchFrom, reinterpret_cast<const uint8_t*>(prefix.data()), prefix.size());
    if (!found)
      break;
    const size_t valStart = (found - buf) + prefix.size();
    if (valStart >= len)
      break;

    size_t valEnd = valStart;
    while (valEnd < len && buf[valEnd] != '"')
      ++valEnd;
    if (valEnd >= len)
      break;

    if (valEnd > valStart) {
      std::memset(buf + valStart, ' ', valEnd - valStart);
      ++edits;
    }
    searchFrom = valEnd + 1;
  }
  return edits;
}

int ProcessXmpPayload(uint8_t* buf, size_t len) {
  int edits = 0;
  for (const char* prop: XmpDateSoftwareProps) {
    edits += WipeXmpElementValue(buf, len, prop);
    edits += WipeXmpAttributeValue(buf, len, prop);
  }
  return edits;
}

int ProcessFile(const std::string& inPath, const std::string& outPath, bool inPlace) {
  std::ifstream in(inPath, std::ios::binary);
  if (!in) {
    std::cout << "Could not open " << inPath << "\n";
    return 1;
  }
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  in.close();

  if (data.size() < 4 || data[0] != 0xFF || data[1] != 0xD8) {
    std::cout << "Skipping %s (not a valid JPEG / missing SOI marker)" << inPath << "\n";
    return 1;
  }

  size_t pos     = 2;
  int totalEdits = 0;
  bool foundExif = false;
  bool foundXmp  = false;

  while (pos + 4 <= data.size()) {
    if (data[pos] != 0xFF) {
      ++pos;
      continue;
    }
    uint8_t marker = data[pos + 1];

    if (marker == 0xD8 || marker == 0xD9) {
      pos += 2;
      continue;
    }
    if (marker >= 0xD0 && marker <= 0xD7) {
      pos += 2;
      continue;
    }
    if (marker == 0x01) {
      pos += 2;
      continue;
    }

    if (pos + 4 > data.size())
      break;
    uint16_t segLen   = Read16(&data[pos + 2], true);
    size_t payloadOff = pos + 4;
    size_t payloadLen = (segLen >= 2) ? segLen - 2 : 0;
    if (payloadOff + payloadLen > data.size())
      break;

    if (marker == 0xE1 && payloadLen > 6 &&
      std::memcmp(&data[payloadOff], "Exif\0\0", 6) == 0) {
      foundExif       = true;
      uint8_t* tiff   = &data[payloadOff + 6];
      size_t tiffSize = payloadLen - 6;
      totalEdits      += ProcessExifPayload(tiff, tiffSize);
    }

    static const char xmpSig[] = "http://ns.adobe.com/xap/1.0/";
    size_t xmpSigLen           = sizeof(xmpSig);
    if (marker == 0xE1 && payloadLen > xmpSigLen &&
      std::memcmp(&data[payloadOff], xmpSig, xmpSigLen - 1) == 0) {
      foundXmp        = true;
      uint8_t* xmpBuf = &data[payloadOff + xmpSigLen];
      size_t xmpLen   = payloadLen - xmpSigLen;
      totalEdits      += ProcessXmpPayload(xmpBuf, xmpLen);
    }

    if (marker == 0xDA)
      break;

    pos = payloadOff + payloadLen;
  }

  if (!foundExif && !foundXmp) {
    std::cout << inPath << ": no EXIF/XMP metadata found - skipped.\n";
    return 0;
  }

  if (inPlace) {
    std::string bak = inPath + ".bak";
    std::ifstream src(inPath, std::ios::binary);
    std::ofstream dst(bak, std::ios::binary);
    dst << src.rdbuf();
  }

  std::ofstream out(outPath, std::ios::binary);
  if (!out) {
    std::cout << "Could not write " << outPath << "\n";
    return 1;
  }
  out.write(reinterpret_cast<char*>(data.data()), data.size());
  out.close();

  std::cout << inPath << ": cleared " << totalEdits << " field(s) across "
    << (foundExif ? "EXIF " : "") << (foundXmp ? "XMP " : "") << "\n";
  return 0;
}

bool HasJpegExtension(const std::filesystem::path& p) {
  std::string ext = p.extension().string();
  for (auto& c: ext)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return ext == ".jpg" || ext == ".jpeg";
}

int main(int argc, char** argv) {
  const bool batchMode = (argc >= 2 && std::string(argv[1]) == "--dir");

  if (batchMode) {
    const std::filesystem::path dir = (argc >= 3) ? argv[2] : ".";

    if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir)) {
      std::cout << "Not a valid directory: " << dir.string() << "\n";
      return 1;
    }

    int filesProcessed = 0;
    int filesFailed    = 0;

    for (const auto& entry: std::filesystem::directory_iterator(dir)) {
      if (!entry.is_regular_file())
        continue;
      if (!HasJpegExtension(entry.path()))
        continue;

      std::string fullPath = entry.path().string();
      if (const int rc = ProcessFile(fullPath, fullPath, true); rc == 0)
        ++filesProcessed;
      else
        ++filesFailed;
    }

    std::cout << "Batch complete: " << filesProcessed << " file(s) processed";

    if (filesFailed > 0)
      std::cout << ", " << filesFailed << " failed/skipped";
    std::cout << "\n";

    if (filesProcessed > 0)
      std::cout << "Each edited file has a .bak backup alongside it\n";
    return filesFailed > 0 && filesProcessed == 0 ? 1 : 0;
  }

  if (argc < 2) {
    std::cout << "Usage:\n"
      "Program input.jpg [output.jpg]   Process a single file\n"
      "Program --dir [folder]           Process every .jpg/.jpeg in folder (default: current dir)\n";
    return 1;
  }

  const std::string inPath  = argv[1];
  const std::string outPath = argc >= 3 ? argv[2] : inPath;
  const bool inPlace        = argc < 3;

  const int rc = ProcessFile(inPath, outPath, inPlace);
  if (rc == 0) {
    if (inPlace)
      std::cout << "Original backed up to " << inPath << ".bak\n";
    std::cout << "Output written to " << outPath << "\n";
  }
  return rc;
}
