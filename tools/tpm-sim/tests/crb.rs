use tpm_sim::tpm_crb::{SIZE, Window};

const BASE: u32 = 0x3ebf_f000;
const START: usize = 0x4c;
const BUFFER: usize = 0x80;

const GET_CAPABILITY_PROPERTIES: [u8; 22] = [
    0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x01,
];

struct Page(Vec<u32>);

impl Page {
    fn new() -> Page {
        Page(vec![0xdead_beef; SIZE as usize / 4])
    }

    fn window(&mut self) -> Window {
        Window::new(self.0.as_mut_ptr() as *mut u8, BASE)
    }

    fn word(&self, offset: usize) -> u32 {
        self.0[offset / 4]
    }

    fn bytes(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0.as_mut_ptr() as *mut u8, SIZE as usize) }
    }

    fn command(&mut self, command: &[u8]) {
        self.bytes()[BUFFER..BUFFER + command.len()].copy_from_slice(command);
        self.0[START / 4] = 1;
    }

    fn response(&mut self) -> Vec<u8> {
        let buffer = &self.bytes()[BUFFER..];
        let length = u32::from_be_bytes(buffer[2..6].try_into().unwrap()) as usize;
        buffer[..length].to_vec()
    }
}

#[test]
fn a_reset_page_describes_the_buffer_and_nothing_else() {
    let mut page = Page::new();
    page.window().reset();
    assert_eq!(page.word(0x58), 2048);
    assert_eq!(page.word(0x5c), BASE + BUFFER as u32);
    assert_eq!(page.word(0x60), 0);
    assert_eq!(page.word(0x64), 2048);
    assert_eq!(page.word(0x68), BASE + BUFFER as u32);
    assert_eq!(page.word(0x6c), 0);
    assert_eq!(page.word(START), 0);
    assert_eq!(page.word(0x44) & 2, 2, "the TPM is idle");
    assert_eq!(page.word(0x0c00), 0, "the rest of the page is clear");
}

#[test]
fn a_command_with_start_set_is_answered_in_the_buffer() {
    let mut page = Page::new();
    page.window().reset();
    page.command(&GET_CAPABILITY_PROPERTIES);
    page.window().answer();
    assert_eq!(page.word(START), 0, "START is cleared once the response is there");
    let response = page.response();
    assert_eq!(&response[..2], &[0x80, 0x01]);
    assert_eq!(&response[6..10], &[0, 0, 0, 0], "TPM_RC_SUCCESS");
    assert!(response.len() > 10);
}

#[test]
fn a_doorbell_without_start_changes_nothing() {
    let mut page = Page::new();
    page.window().reset();
    page.bytes()[BUFFER..BUFFER + 22].copy_from_slice(&GET_CAPABILITY_PROPERTIES);
    page.window().answer();
    assert_eq!(&page.bytes()[BUFFER..BUFFER + 22], &GET_CAPABILITY_PROPERTIES);
}

#[test]
fn a_command_longer_than_the_buffer_gets_a_command_size_error() {
    let mut page = Page::new();
    page.window().reset();
    let mut command = GET_CAPABILITY_PROPERTIES;
    command[2..6].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    page.command(&command);
    page.window().answer();
    assert_eq!(page.word(START), 0);
    let response = page.response();
    assert_eq!(response.len(), 10);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0x142);
}

#[test]
fn the_page_cannot_move_the_buffer() {
    let mut page = Page::new();
    page.window().reset();
    page.0[0x5c / 4] = 0x1000;
    page.0[0x64 / 4] = 0x7fff_ffff;
    page.command(&GET_CAPABILITY_PROPERTIES);
    page.window().answer();
    assert_eq!(&page.response()[6..10], &[0, 0, 0, 0]);
}
