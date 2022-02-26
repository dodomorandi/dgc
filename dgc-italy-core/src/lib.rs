// #![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod settings;
use std::ops::{Not, RangeInclusive};

use chrono::{offset, Datelike, Local, NaiveDate};
use dgc::{Dgc, Recovery, Vaccination};

pub use settings::Settings;
use settings::{Interval, VaccineSettings, Vaccines};

const COUNTRY_ITALY: &str = "IT";
const COUNTRY_SAN_MARINO: &str = "SM";

mod sealed {
    pub trait Sealed {}
}

pub trait DgcItalyExt: sealed::Sealed {
    fn check(&self, scan_mode: ScanMode, settings: &Settings) -> Validity;
}

impl sealed::Sealed for Dgc {}

impl DgcItalyExt for Dgc {
    fn check(&self, scan_mode: ScanMode, settings: &Settings) -> Validity {
        use ScanMode::*;

        // TODO: check signature validify based on trustlist.
        // TODO: check disease agent
        // TODO: check EU DGC
        // TODO: check blacklist
        // TODO: check revocation list
        // TODO: exhemption

        if self
            .tests
            .iter()
            .max_by_key(|test| test.date_of_collection)
            .is_some()
        {
            match scan_mode {
                Base | EntryItaly => Validity::Valid,
                Work => {
                    let is_valid = self
                        .date_of_birth
                        .map(is_date_of_birth_below_threshold)
                        .unwrap_or(false);

                    match is_valid {
                        true => Validity::Valid,
                        false => Validity::NotValid,
                    }
                }
                Strenghtened | Booster | School => Validity::NotValid,
            }
        } else if let Some(vaccination) = self
            .vaccines
            .iter()
            .max_by_key(|vaccination| vaccination.date)
        {
            check_vaccination(self, vaccination, scan_mode, settings)
        } else if let Some(recovery) = self
            .recoveries
            .iter()
            .max_by_key(|recovery| recovery.valid_from)
        {
            check_recovery(recovery, scan_mode, settings)
        } else {
            Validity::NotValid
        }
    }
}

/// Age since the vaccination is required.
pub const VALIDATION_AGE_LIMIT_YEARS: u8 = 50;

fn is_date_of_birth_below_threshold(date_of_birth: NaiveDate) -> bool {
    use std::cmp::Ordering;

    let today = offset::Local::today().naive_local();
    match (today.year() - date_of_birth.year()).cmp(&VALIDATION_AGE_LIMIT_YEARS.into()) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal if today.ordinal() < date_of_birth.ordinal() => true,
        Ordering::Equal => false,
    }
}

/// A set of _scan modes_ to be used for the verification of the Digital Green Pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanMode {
    /// Basic validation mode, only vaccination, healing or test is required.
    Base,
    /// Validation mode that requires at least healing or vaccination.
    Strenghtened,
    /// Strongest validation mode, which requires at least a full vaccination cycle and a further
    /// level of health proof. This scan mode is required for nursing home visitors.
    Booster,
    /// Validation mode for students. It requires at least a full vaccination cycle or a recovery,
    /// and this information cannot be older than 120 days.
    ///
    /// **Warning**: this scan mode cannot be implemented by non-official libraries, therefore this
    /// cannot be used in practice.
    School,
    /// Validation mode for work. It requires a vaccination, a recovery or a test for people under
    /// age of 50.
    Work,
    /// Validation required to entry into Italy. It requires a full vaccination cycle not older
    /// than 270 days (and a test if vaccination is older than 180 days or the vaccine is not in
    /// the [EMA list]), a recovery or a test.
    ///
    /// [EMA list]: https://www.ema.europa.eu/en/human-regulatory/overview/public-health-threats/coronavirus-disease-covid-19/treatments-vaccines/vaccines-covid-19/covid-19-vaccines-authorised
    EntryItaly,
}

impl Default for ScanMode {
    fn default() -> Self {
        Self::Base
    }
}

/// Level of validity for the [`Dgc`] given a specific [`ScanMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Validity {
    /// The certificate is not valid.
    NotValid,
    /// The certificate is valid if a valid test is exhibited.
    TestNeeded,
    /// The certificate is valid.
    Valid,
}

fn get_validity_range(date: NaiveDate, interval: Interval) -> RangeInclusive<NaiveDate> {
    let start = date + chrono::Duration::days(interval.start_day.into());
    let end = start + chrono::Duration::days(interval.end_day.into());

    start..=end
}

fn check_recovery(recovery: &Recovery, scan_mode: ScanMode, settings: &Settings) -> Validity {
    let is_post_vaccination_recovery =
        &*recovery.country == COUNTRY_ITALY && recovery.id.is_recovery();

    let certificate_interval = if is_post_vaccination_recovery {
        settings.recovery.pv_cert
    } else if matches!(scan_mode, ScanMode::EntryItaly) {
        settings.recovery.cert_not_it
    } else {
        settings.recovery.cert_it
    };

    let recovery_validity =
        recovery.valid_from.naive_local().date()..=recovery.valid_until.naive_local().date();

    let today = Local::today().naive_local();
    let is_valid_today = if recovery_validity.contains(&today) {
        get_validity_range(*recovery_validity.start(), certificate_interval).contains(&today)
    } else {
        false
    };

    if is_valid_today {
        Validity::NotValid
    } else if matches!(scan_mode, ScanMode::Booster) && is_post_vaccination_recovery.not() {
        Validity::TestNeeded
    } else {
        Validity::Valid
    }
}

fn check_vaccination(
    dgc: &Dgc,
    vaccination: &Vaccination,
    scan_mode: ScanMode,
    settings: &Settings,
) -> Validity {
    use std::cmp::Ordering::*;

    enum Status {
        Incomplete,
        Complete,
        Booster,
    }

    let vaccine = MedicinalProduct::new(&*vaccination.medicinal_product);

    let vaccination_status = match (
        vaccination.dose_number.cmp(&vaccination.total_doses),
        vaccine,
        vaccination.dose_number,
    ) {
        (Less, _, _) => Status::Incomplete,
        (Greater | Equal, Some(MedicinalProduct::Janssen), 2..) | (Greater | Equal, _, 3..) => {
            Status::Booster
        }
        (Greater | Equal, _, _) => Status::Complete,
    };

    let ema_product = vaccine.filter(|vaccine| {
        matches!(vaccine, MedicinalProduct::SputnikV).not()
            || vaccination.country == COUNTRY_SAN_MARINO
    });

    let (vaccination_interval, vaccine_end_day_extended, test_required) =
        match (scan_mode, ema_product, vaccination_status) {
            (ScanMode::Base | ScanMode::EntryItaly, None, _)
            | (ScanMode::EntryItaly | ScanMode::Booster, _, Status::Incomplete)
            | (ScanMode::Strenghtened | ScanMode::Work, None, Status::Incomplete)
            | (ScanMode::School, _, _) => return Validity::NotValid,

            (ScanMode::Work, None, _)
                if dgc
                    .date_of_birth
                    .map(is_date_of_birth_below_threshold)
                    .unwrap_or(true) =>
            {
                return Validity::NotValid
            }

            (
                ScanMode::Base | ScanMode::Strenghtened | ScanMode::Work,
                Some(vaccine),
                Status::Incomplete,
            ) => (
                &vaccine.get_settings(&settings.vaccines).not_complete,
                None,
                false,
            ),

            (ScanMode::Base | ScanMode::Booster, _, Status::Complete) => (
                &settings.generic_vaccine.complete_it,
                None,
                matches!(scan_mode, ScanMode::Booster),
            ),

            (ScanMode::Strenghtened, _, Status::Complete) => {
                let is_not_ema = ema_product.is_none();
                let vaccine_end_day_extended = (vaccination.country != COUNTRY_ITALY || is_not_ema)
                    .then(|| settings.generic_vaccine.complete_extended_ema_end_day);

                (
                    &settings.generic_vaccine.complete_it,
                    vaccine_end_day_extended,
                    is_not_ema,
                )
            }

            (ScanMode::Work, _, Status::Complete) => {
                let age_below_threshold = match dgc.date_of_birth {
                    Some(dob) => is_date_of_birth_below_threshold(dob),
                    None => return Validity::NotValid,
                };
                let is_not_ema = ema_product.is_none();
                let (vaccine_end_day_extended, test_required) = if age_below_threshold.not()
                    && (vaccination.country != COUNTRY_ITALY || is_not_ema)
                {
                    (
                        Some(settings.generic_vaccine.complete_extended_ema_end_day),
                        is_not_ema,
                    )
                } else {
                    (None, false)
                };

                (
                    &settings.generic_vaccine.complete_it,
                    vaccine_end_day_extended,
                    test_required,
                )
            }

            (ScanMode::Base | ScanMode::Booster | ScanMode::Work, _, Status::Booster) => (
                &settings.generic_vaccine.booster_it,
                None,
                matches!(scan_mode, ScanMode::Booster) && ema_product.is_none(),
            ),

            (ScanMode::Strenghtened, _, Status::Booster) => (
                &settings.generic_vaccine.booster_it,
                None,
                ema_product.is_none(),
            ),

            (ScanMode::EntryItaly, Some(_), Status::Complete) => {
                (&settings.generic_vaccine.complete_not_it, None, false)
            }

            (ScanMode::EntryItaly, Some(_), Status::Booster) => {
                (&settings.generic_vaccine.booster_not_it, None, false)
            }
        };

    let validity_range =
        get_validity_range(vaccination.date.naive_local().date(), *vaccination_interval);

    let today = Local::today().naive_local();
    if validity_range.contains(&today) {
        if test_required {
            Validity::TestNeeded
        } else {
            Validity::Valid
        }
    } else {
        if let Some(vaccine_end_day_extended) = vaccine_end_day_extended {
            let new_validity_end =
                *validity_range.end() + chrono::Duration::days(vaccine_end_day_extended.into());

            if today <= new_validity_end {
                return Validity::TestNeeded;
            }
        }

        Validity::NotValid
    }
}

#[derive(Clone, Copy)]
enum MedicinalProduct {
    Janssen,
    Vaxzevria,
    Spikevax,
    Comirnaty,
    Covishield,
    RCovi,
    Recombinant,
    SputnikV,
}

impl MedicinalProduct {
    fn new(raw: &str) -> Option<Self> {
        use MedicinalProduct::*;

        Some(match raw {
            "EU/1/20/1525" => Janssen,
            "EU/1/21/1529" => Vaxzevria,
            "EU/1/20/1507" => Spikevax,
            "EU/1/20/1528" => Comirnaty,
            "Covishield" => Covishield,
            "R-COVI" => RCovi,
            "Covid-19-recombinant" => Recombinant,
            "Sputnik-V" => SputnikV,
            _ => return None,
        })
    }

    fn get_settings(self, vaccines: &Vaccines) -> &VaccineSettings {
        use MedicinalProduct::*;

        match self {
            Janssen => &vaccines.janssen,
            Vaxzevria => &vaccines.vaxzevria,
            Spikevax => &vaccines.spikevax,
            Comirnaty => &vaccines.comirnaty,
            Covishield => &vaccines.covishield,
            RCovi => &vaccines.r_covi,
            Recombinant => &vaccines.recombinant,
            SputnikV => &vaccines.sputnik_v,
        }
    }
}
