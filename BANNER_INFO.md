# 🎨 Sud0Recon Dynamic Banner System

Sud0Recon now features a beautiful, dynamic banner system that randomly selects from 8 unique color themes each time you run the tool!

## ✨ Features

- **8 Unique Color Themes**: Each with its own personality and style
- **Random Selection**: Different theme every time you run the tool
- **Professional Design**: Clean, modern ASCII art with emojis
- **Theme Indicator**: Shows which theme is currently active
- **Consistent Branding**: All themes maintain the Sud0Recon identity

## 🎭 Available Themes

1. **Classic Red Hacker** - Traditional hacker red/cyan combination
2. **Matrix Green** - Iconic green terminal style 
3. **Ocean Blue** - Cool blue professional look
4. **Neon Purple** - Vibrant purple cyberpunk vibes
5. **Electric Gold** - Bright golden energy
6. **Cyber Cyan** - Futuristic cyan glow
7. **Clean Terminal** - Minimalist white/blue
8. **Fire Orange** - Bold orange flames

## 🚀 How It Works

The banner system uses Python's `random.choice()` to select a different color scheme each time you run Sud0Recon. Each theme includes:

- **Main Colors**: 3 gradient colors for the ASCII art
- **Accent Color**: For highlights and special text
- **Border Color**: For the panel border
- **Theme Name**: Displayed subtly in the banner

## 🛠 Technical Details

The banner is built using the Rich library for beautiful terminal formatting:
- Unicode block characters for clean ASCII art
- Rich color styling with 256-color and RGB support
- Panel component with dynamic borders
- Text formatting with emojis and styling

## 📋 Usage

Simply run Sud0Recon normally - the banner appears automatically:

```bash
# Each run will show a different theme
sud0recon --version
sud0recon -t example.com
sud0recon --help
```

## 🎪 Demo Script

Run the banner demo to see all themes:

```bash
python demo_banner.py
```

This will cycle through all 8 themes so you can see them all in action!

## 🎯 Benefits

- **Visual Appeal**: Makes the tool more engaging and professional
- **Brand Recognition**: Consistent Sud0Recon identity across all themes
- **User Experience**: Adds personality and variety to each session
- **Terminal Friendly**: Works great in any terminal that supports colors

---

*The banner is more than just decoration - it's part of the Sud0Recon experience! 🔥*
