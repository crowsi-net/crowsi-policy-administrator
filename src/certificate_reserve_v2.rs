use crate::{
    CertificateExecutionReservationV2, CertificatePolicyAdministratorV2,
    CertificateReservationInputV2, Result,
};

impl CertificatePolicyAdministratorV2 {
    /// Reserves one exact certificate authorization and applies its fence CAS.
    ///
    /// # Errors
    ///
    /// Rejects untrusted, replayed, cross-bound, stale, or concurrently fenced input.
    pub fn reserve_certificate_execution_v2(
        &mut self,
        input: &CertificateReservationInputV2<'_>,
    ) -> Result<CertificateExecutionReservationV2> {
        crate::certificate_normalizer_v2::verify(self, input)?;
        let now = self.clock.now();
        let now_epoch_s = crate::clock::epoch_seconds(&now)?;
        self.verify_reservation(input, now_epoch_s)?;
        self.commit_certificate_reservation(input)
    }
}
