use crowsi_control_contracts::certificate_target_normalization_digest_v2;

use crate::{
    AdministratorError, CertificatePolicyAdministratorV2, CertificateReservationInputV2, Result,
};

/// Independently canonicalizes provider input using a pinned implementation.
pub trait TargetResourceNormalizerVerifierPortV2: Send + Sync {
    fn canonicalize(
        &self,
        normalizer_id: &str,
        normalizer_version: &str,
        provider: &str,
        raw_provider_scoped_target: &str,
    ) -> Option<String>;
}

pub(crate) struct SimulationExactTargetNormalizerV2;

impl TargetResourceNormalizerVerifierPortV2 for SimulationExactTargetNormalizerV2 {
    fn canonicalize(
        &self,
        _: &str,
        _: &str,
        _: &str,
        raw_provider_scoped_target: &str,
    ) -> Option<String> {
        (!raw_provider_scoped_target.is_empty()).then(|| raw_provider_scoped_target.into())
    }
}

pub(crate) fn verify(
    administrator: &CertificatePolicyAdministratorV2,
    input: &CertificateReservationInputV2<'_>,
) -> Result<()> {
    let normalizer = administrator
        .target_normalizer
        .as_ref()
        .ok_or(AdministratorError::CertificateAuthorizationUnavailable)?;
    let target = &input.command.binding.target;
    let canonical = normalizer
        .canonicalize(
            &target.target_resource_normalizer_id,
            &target.target_resource_normalizer_version,
            &target.provider,
            input.target_resource_raw_input,
        )
        .ok_or(AdministratorError::Binding)?;
    let digest = certificate_target_normalization_digest_v2(
        &target.provider,
        input.target_resource_raw_input,
        &canonical,
        &target.target_resource_normalizer_id,
        &target.target_resource_normalizer_version,
    );
    let exact = target.target_resource_normalization_verified
        && canonical == target.target_resource_id
        && digest == target.target_resource_normalization_digest_sha256;
    exact.then_some(()).ok_or(AdministratorError::Binding)
}
