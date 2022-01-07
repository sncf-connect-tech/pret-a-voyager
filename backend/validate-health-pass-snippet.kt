private suspend fun validateHealthPass(
    healthPassRequest: HealthPassRequest,
    travelDate: OffsetDateTime,
    ticket: Ticket,
): Result<Unit, HealthPassError> {

    return when (healthPassRequest.passType) {
        HealthPassType.DCC -> tacVerifClient.validateDCCPass(healthPassRequest.passContent, healthPassRequest.publicKey, travelDate)
        else -> tacVerifClient.validate2DDocPass(healthPassRequest.passContent, healthPassRequest.publicKey, travelDate)
    }
        .mapError {
            when (it.httpStatus) {
                // Tac Verif sends a 404 when the health pass content is malformed
                HttpStatus.NOT_FOUND -> HealthPassError.CertificateMalformed
                else -> HealthPassError.UnexpectedError
            }
        }
        .andThen {
            val ticketLastnameNormalized = normalizeName(ticket.lastname)
            val ticketFirstNameNormalized = normalizeName(ticket.firstname)
            val ticketBirthdate = ticket.birthdate
            val informations = it.data.dynamic[0]
            val healthPassLastnameNormalized = normalizeName(informations.liteLastName)
            val healthPassFirstNameNormalized = normalizeName(informations.liteFirstName)
            val healthPassBirthdate = informations.liteDateOfBirth
            val validityStatus = informations.liteValidityStatus
            val isBlacklisted = it.data.static.isBlacklisted

            when {
                healthPassLastnameNormalized != ticketLastnameNormalized && !healthPassRequest.allowLastnameMismatch ->
                    Err(HealthPassError.LastnameNotMatching(ticketLastnameNormalized, healthPassLastnameNormalized))
                healthPassFirstNameNormalized != ticketFirstNameNormalized ->
                    Err(HealthPassError.FirstnameNotMatching(ticketFirstNameNormalized, healthPassFirstNameNormalized))
                healthPassBirthdate != ticketBirthdate ->
                    Err(HealthPassError.BirthdateNotMatching(ticketBirthdate, healthPassBirthdate))
                validityStatus == LiteValidityStatus.CERTIFICAT_FRAUDULEUX || isBlacklisted ->
                    Err(HealthPassError.HealthPassBlacklisted)
                validityStatus == LiteValidityStatus.VALIDE -> Ok(Unit)
                else -> Err(HealthPassError.HealthPassNotValid)
            }
        }
}

fun normalizeName(name: String) =
    StringUtils.stripAccents(name).trim().uppercase().replace("-", " ")
