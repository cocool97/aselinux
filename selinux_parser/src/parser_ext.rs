pub trait ParserExt {
    type Output<'a>;

    /// Parses `input` into [`Self::Output`], borrowing from it.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ParserError::Syntax`] on the first line that cannot be parsed.
    fn parse(input: &[u8]) -> crate::Result<Self::Output<'_>>;
}
