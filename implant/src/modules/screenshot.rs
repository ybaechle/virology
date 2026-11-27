// Capture d'écran, retournée en base64 PNG.
pub fn run(_args: &str) -> String {
    #[cfg(windows)]
    return capture_windows();
    #[cfg(not(windows))]
    "capture d'écran disponible sur Windows uniquement".to_string()
}

#[cfg(windows)]
fn capture_windows() -> String {
    use base64::Engine;
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject,
        GetDC, GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER,
        DIB_RGB_COLORS, SRCCOPY, BI_RGB,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

    unsafe {
        let hdc_screen = GetDC(0);
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);

        let hdc_mem = CreateCompatibleDC(hdc_screen);
        let hbmp = CreateCompatibleBitmap(hdc_screen, width, height);
        let old = SelectObject(hdc_mem, hbmp);
        BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [std::mem::zeroed()],
        };

        let buf_size = (width * height * 4) as usize;
        let mut buf = vec![0u8; buf_size];
        GetDIBits(hdc_mem, hbmp, 0, height as u32, buf.as_mut_ptr().cast(), &mut bmi, DIB_RGB_COLORS);

        SelectObject(hdc_mem, old);
        DeleteObject(hbmp);
        DeleteDC(hdc_mem);
        ReleaseDC(0, hdc_screen);

        // Downsample 4× pour réduire le payload (~500 Ko au lieu de ~8 Mo).
        let w4 = (width / 4) as usize;
        let h4 = (height / 4) as usize;
        let mut small = Vec::with_capacity(w4 * h4 * 4);
        for y in 0..h4 {
            for x in 0..w4 {
                let src = (y * 4 * width as usize + x * 4) * 4;
                small.extend_from_slice(&buf[src..src + 4]);
            }
        }

        let b64 = base64::engine::general_purpose::STANDARD.encode(&small);
        format!("__FILE__screenshot.raw__:{}:{}\n{}", w4, h4, b64)
    }
}
