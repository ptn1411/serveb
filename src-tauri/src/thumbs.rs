// Small JPEG previews for the photo grid. A phone photo is 3–5 MB; its thumbnail is
// ~20–40 KB, so a folder of hundreds of photos scrolls smoothly over Wi-Fi.
//
// Thumbnails are cached on disk (app cache dir), keyed by path + size + modification
// time: each photo is decoded once, and an edited photo automatically gets a new one.
// The key uses std's hasher, so a Rust upgrade may just cause a one-off re-render.

use image::{codecs::jpeg::JpegEncoder, metadata::Orientation, DynamicImage, ImageDecoder, ImageReader};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;

/// Longest side of a thumbnail — enough for a ~120 pt grid tile on a 3× iPhone screen.
pub const THUMB_PX: u32 = 360;
const QUALITY: u8 = 78;
/// Don't try to decode anything bigger (huge panoramas, corrupt files…).
const MAX_SOURCE_BYTES: u64 = 80 * 1024 * 1024;
/// Decoding is CPU-heavy: cap how many run at once so the PC stays responsive.
const PARALLEL: usize = 3;
/// Disk cache budget; the oldest thumbnails go first when it is exceeded.
pub const CACHE_MAX_BYTES: u64 = 300 * 1024 * 1024;

/// Formats we can decode. (iPhone HEIC photos are not among them.)
pub const EXTENSIONS: [&str; 7] = ["jpg", "jpeg", "jfif", "png", "gif", "webp", "bmp"];

pub fn supported(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

#[derive(Debug)]
pub enum ThumbError {
    NotFound,
    Unsupported,
    TooLarge,
    Failed(String),
}

pub struct Thumbs {
    dir: PathBuf,
    slots: Semaphore,
}

impl Thumbs {
    pub fn new(dir: PathBuf) -> Self {
        Thumbs {
            dir,
            slots: Semaphore::new(PARALLEL),
        }
    }

    /// JPEG bytes of the thumbnail for `path` — from the cache, or made now.
    pub async fn get(&self, path: &Path) -> Result<Vec<u8>, ThumbError> {
        let meta = tokio::fs::metadata(path).await.map_err(|_| ThumbError::NotFound)?;
        if !meta.is_file() {
            return Err(ThumbError::NotFound);
        }
        if !supported(path) {
            return Err(ThumbError::Unsupported);
        }
        if meta.len() > MAX_SOURCE_BYTES {
            return Err(ThumbError::TooLarge);
        }
        let cached = self.dir.join(format!("{}.jpg", cache_key(path, &meta)));
        if let Ok(bytes) = tokio::fs::read(&cached).await {
            return Ok(bytes);
        }

        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|e| ThumbError::Failed(e.to_string()))?;
        // Another request may have made it while this one waited for a slot.
        if let Ok(bytes) = tokio::fs::read(&cached).await {
            return Ok(bytes);
        }
        let src = path.to_path_buf();
        let bytes = tokio::task::spawn_blocking(move || make(&src))
            .await
            .map_err(|e| ThumbError::Failed(e.to_string()))?
            .map_err(ThumbError::Failed)?;

        // Best effort. Write-then-rename so a half-written file is never served.
        let _ = tokio::fs::create_dir_all(&self.dir).await;
        let tmp = cached.with_extension(format!("tmp{:08x}", rand::random::<u32>()));
        if tokio::fs::write(&tmp, &bytes).await.is_ok()
            && tokio::fs::rename(&tmp, &cached).await.is_err()
        {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        Ok(bytes)
    }
}

fn cache_key(path: &Path, meta: &std::fs::Metadata) -> String {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    meta.len().hash(&mut h);
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .hash(&mut h);
    (THUMB_PX, QUALITY).hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Decode (honouring EXIF rotation — iPhone photos are often stored sideways),
/// shrink to fit `THUMB_PX`, and encode as JPEG.
pub fn make(path: &Path) -> Result<Vec<u8>, String> {
    let err = |e: &dyn std::fmt::Display| e.to_string();
    let mut decoder = ImageReader::open(path)
        .map_err(|e| err(&e))?
        .with_guessed_format()
        .map_err(|e| err(&e))?
        .into_decoder()
        .map_err(|e| err(&e))?;
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
    let mut img = DynamicImage::from_decoder(decoder).map_err(|e| err(&e))?;
    img.apply_orientation(orientation);
    if img.width() > THUMB_PX || img.height() > THUMB_PX {
        img = img.thumbnail(THUMB_PX, THUMB_PX);
    }
    let mut out = Vec::with_capacity(48 * 1024);
    JpegEncoder::new_with_quality(&mut out, QUALITY)
        .encode_image(&img.to_rgb8())
        .map_err(|e| err(&e))?;
    Ok(out)
}

/// Keep the cache under `max` bytes by deleting the oldest thumbnails (down to ¾).
pub fn prune(dir: &Path, max: u64) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(SystemTime, u64, PathBuf)> = read
        .filter_map(Result::ok)
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            m.is_file()
                .then(|| (m.modified().unwrap_or(UNIX_EPOCH), m.len(), e.path()))
        })
        .collect();
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    if total <= max {
        return;
    }
    files.sort_by_key(|f| f.0);
    for (_, len, path) in files {
        if total <= max / 4 * 3 {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total -= len;
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use image::{ImageFormat, RgbImage};

    /// A width×height JPEG, optionally tagged with an EXIF orientation.
    pub fn jpeg(width: u32, height: u32, exif_orientation: Option<u16>) -> Vec<u8> {
        let img = RgbImage::from_fn(width, height, |x, y| image::Rgb([(x % 256) as u8, (y % 256) as u8, 90]));
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, ImageFormat::Jpeg).unwrap();
        let jpeg = out.into_inner();
        let Some(o) = exif_orientation else {
            return jpeg;
        };
        // Minimal APP1/Exif segment: little-endian TIFF with a single Orientation tag.
        let mut tiff = vec![b'I', b'I', 0x2A, 0x00, 8, 0, 0, 0, 1, 0, 0x12, 0x01, 3, 0, 1, 0, 0, 0];
        tiff.extend_from_slice(&o.to_le_bytes());
        tiff.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let mut app1 = vec![0xFF, 0xE1];
        app1.extend_from_slice(&((2 + 6 + tiff.len()) as u16).to_be_bytes());
        app1.extend_from_slice(b"Exif\0\0");
        app1.extend_from_slice(&tiff);
        [&jpeg[..2], &app1[..], &jpeg[2..]].concat()
    }

    fn dims(bytes: &[u8]) -> (u32, u32) {
        let img = image::load_from_memory(bytes).unwrap();
        (img.width(), img.height())
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("namsv-thumb-{:x}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn shrinks_keeps_aspect_and_honours_exif_rotation() {
        let d = tmp();
        std::fs::write(d.join("wide.jpg"), jpeg(1200, 600, None)).unwrap();
        std::fs::write(d.join("sideways.jpg"), jpeg(1200, 600, Some(6))).unwrap();
        std::fs::write(d.join("small.jpg"), jpeg(100, 50, None)).unwrap();
        assert_eq!(dims(&make(&d.join("wide.jpg")).unwrap()), (360, 180));
        // Orientation 6 = rotate 90°: the stored landscape pixels display as portrait.
        assert_eq!(dims(&make(&d.join("sideways.jpg")).unwrap()), (180, 360));
        // Never upscaled.
        assert_eq!(dims(&make(&d.join("small.jpg")).unwrap()), (100, 50));
        assert!(supported(Path::new("A.JPG")) && !supported(Path::new("a.heic")));
    }

    #[tokio::test]
    async fn caches_on_disk_and_refreshes_when_the_photo_changes() {
        let d = tmp();
        let cache = d.join("cache");
        let photo = d.join("p.png");
        let png = |w, h| {
            let mut out = std::io::Cursor::new(Vec::new());
            RgbImage::new(w, h).write_to(&mut out, ImageFormat::Png).unwrap();
            out.into_inner()
        };
        std::fs::write(&photo, png(800, 800)).unwrap();
        let t = Thumbs::new(cache.clone());
        let a = t.get(&photo).await.unwrap();
        assert_eq!(dims(&a), (360, 360));
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1);
        assert_eq!(t.get(&photo).await.unwrap(), a); // served from cache

        // Replacing the photo (new size/mtime) yields a new thumbnail.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&photo, png(400, 800)).unwrap();
        assert_eq!(dims(&t.get(&photo).await.unwrap()), (180, 360));
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 2);

        assert!(matches!(t.get(&d.join("missing.jpg")).await, Err(ThumbError::NotFound)));
        std::fs::write(d.join("x.txt"), "hi").unwrap();
        assert!(matches!(t.get(&d.join("x.txt")).await, Err(ThumbError::Unsupported)));
        std::fs::write(d.join("broken.jpg"), "not an image").unwrap();
        assert!(matches!(t.get(&d.join("broken.jpg")).await, Err(ThumbError::Failed(_))));

        // Pruning drops the oldest entries once over budget.
        prune(&cache, 1);
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
    }
}
