use leptos::{mount_to_body, view};

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <p> "Hello, world!" </p>})
}
