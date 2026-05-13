const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

// Read the flag image
const flagPath = path.join(__dirname, 'public', 'alberta-flag.png');

async function makeIcons() {
  try {
    // Ensure file exists
    if (!fs.existsSync(flagPath)) {
      console.error('Flag image not found:', flagPath);
      return;
    }

    // Generate 192x192 icon
    await sharp(flagPath)
      .resize(192, 192, { fit: 'cover' })
      .png()
      .toFile('public/icon-192.png');
    console.log('Created icon-192.png');

    // Generate 512x512 icon
    await sharp(flagPath)
      .resize(512, 512, { fit: 'cover' })
      .png()
      .toFile('public/icon-512.png');
    console.log('Created icon-512.png');

    console.log('Icons created!');
  } catch (err) {
    console.error('Error:', err);
  }
}

makeIcons();