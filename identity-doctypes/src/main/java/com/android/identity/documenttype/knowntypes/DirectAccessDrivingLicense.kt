/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity.documenttype.knowntypes

import com.android.identity.documenttype.DocumentAttributeType
import com.android.identity.documenttype.DocumentType
import com.android.identity.documenttype.StringOption

/**
 * Object containing the metadata of the Driving License
 * Credential Type.
 */
object DirectAccessDrivingLicense {
    const val MDL_NAMESPACE = "org.iso.18013.5.1"

    /**
     * Build the Driving License Credential Type.
     */
    fun getDocumentType(): DocumentType {
        return DocumentType.Builder("DA Driving License")
            .addMdocDocumentType("org.iso.18013.5.1.mDL")
            .addVcDocumentType("Iso18013DriversLicenseCredential")/*
             * First the attributes that the mDL and VC Credential Type have in common
             */
            .addAttribute(
                DocumentAttributeType.String,
                "family_name",
                "Family Name",
                "Last name, surname, or primary identifier, of the mDL holder.",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "given_name",
                "Given Names",
                "First name(s), other name(s), or secondary identifier, of the mDL holder",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "birth_date",
                "Date of Birth",
                "Day, month and year on which the mDL holder was born. If unknown, approximate date of birth",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "issue_date",
                "Date of Issue",
                "Date when mDL was issued",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Date,
                "expiry_date",
                "Date of Expiry",
                "Date when mDL expires",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.StringOptions(Options.COUNTRY_ISO_3166_1_ALPHA_2),
                "issuing_country",
                "Issuing Country",
                "Alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "issuing_authority",
                "Issuing Authority",
                "Issuing authority name.",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "document_number",
                "License Number",
                "The number assigned or calculated by the issuing authority.",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Picture,
                "portrait",
                "Photo of Holder",
                "A reproduction of the mDL holder’s portrait.",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.ComplexType,
                "driving_privileges",
                "Driving Privileges",
                "Driving privileges of the mDL holder",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.StringOptions(Options.DISTINGUISHING_SIGN_ISO_IEC_18013_1_ANNEX_F),
                "un_distinguishing_sign",
                "UN Distinguishing Sign",
                "Distinguishing sign of the issuing country",
                true,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "administrative_number",
                "Administrative Number",
                "An audit control number assigned by the issuing authority",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.IntegerOptions(Options.SEX_ISO_IEC_5218),
                "sex",
                "Sex",
                "mDL holder’s sex",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Number,
                "height",
                "Height",
                "mDL holder’s height in centimetres",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Number,
                "weight",
                "Weight",
                "mDL holder’s weight in kilograms",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.StringOptions(
                    listOf(
                        StringOption(null, "(not set)"),
                        StringOption("black", "Black"),
                        StringOption("blue", "Blue"),
                        StringOption("brown", "Brown"),
                        StringOption("dichromatic", "Dichromatic"),
                        StringOption("grey", "Grey"),
                        StringOption("green", "Green"),
                        StringOption("hazel", "Hazel"),
                        StringOption("maroon", "Maroon"),
                        StringOption("pink", "Pink"),
                        StringOption("unknown", "Unknown")
                    )
                ),
                "eye_colour",
                "Eye Color",
                "mDL holder’s eye color",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.StringOptions(
                    listOf(
                        StringOption(null, "(not set)"),
                        StringOption("bald", "Bald"),
                        StringOption("black", "Black"),
                        StringOption("blond", "Blond"),
                        StringOption("brown", "Brown"),
                        StringOption("grey", "Grey"),
                        StringOption("red", "Red"),
                        StringOption("auburn", "Auburn"),
                        StringOption("sandy", "Sandy"),
                        StringOption("white", "White"),
                        StringOption("unknown", "Unknown"),
                    )
                ),
                "hair_colour",
                "Hair Color",
                "mDL holder’s hair color",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "birth_place",
                "Place of Birth",
                "Country and municipality or state/province where the mDL holder was born",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "resident_address",
                "Resident Address",
                "The place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.)",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "portrait_capture_date",
                "Portrait Image Timestamp",
                "Date when portrait was taken",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Number,
                "age_in_years",
                "Age in Years",
                "The age of the mDL holder",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Number,
                "age_birth_year",
                "Year of Birth",
                "The year when the mDL holder was born",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Boolean,
                "age_over_18",
                "Older Than 18 Years",
                "Indication whether the mDL holder is as old or older than 18",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Boolean,
                "age_over_21",
                "Older Than 21 Years",
                "Indication whether the mDL holder is as old or older than 21",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Boolean,
                "age_over_25",
                "Older Than 25 Years",
                "Indication whether the mDL holder is as old or older than 25",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Boolean,
                "age_over_62",
                "Older Than 62 Years",
                "Indication whether the mDL holder is as old or older than 62",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Boolean,
                "age_over_65",
                "Older Than 65 Years",
                "Indication whether the mDL holder is as old or older than 65",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "issuing_jurisdiction",
                "Issuing Jurisdiction",
                "Country subdivision code of the jurisdiction that issued the mDL",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.StringOptions(Options.COUNTRY_ISO_3166_1_ALPHA_2),
                "nationality",
                "Nationality",
                "Nationality of the mDL holder",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "resident_city",
                "Resident City",
                "The city where the mDL holder lives",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "resident_state",
                "Resident State",
                "The state/province/district where the mDL holder lives",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "resident_postal_code",
                "Resident Postal Code",
                "The postal code of the mDL holder",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.StringOptions(Options.COUNTRY_ISO_3166_1_ALPHA_2),
                "resident_country",
                "Resident Country",
                "The country where the mDL holder lives",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "family_name_national_character",
                "Family Name National Characters",
                "The family name of the mDL holder",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.String,
                "given_name_national_character",
                "Given Name National Characters",
                "The given name of the mDL holder",
                false,
                MDL_NAMESPACE
            )
            .addAttribute(
                DocumentAttributeType.Picture,
                "signature_usual_mark",
                "Signature / Usual Mark",
                "Image of the signature or usual mark of the mDL holder,",
                false,
                MDL_NAMESPACE
            )
            // TODO Uncomment below code once fixes are merged in mdlApplet.
            /*
             * Then the attributes that exist only in the mDL Credential Type and not in the VC Credential Type
             */
            // .addMdocAttribute(
            //     DocumentAttributeType.Picture,
            //     "biometric_template_face",
            //     "Biometric Template Face",
            //     "Facial biometric information of the mDL holder",
            //     false,
            //     MDL_NAMESPACE
            // )
            // .addMdocAttribute(
            //     DocumentAttributeType.Picture,
            //     "biometric_template_finger",
            //     "Biometric Template Fingerprint",
            //     "Fingerprint of the mDL holder",
            //     false,
            //     MDL_NAMESPACE
            // )
            // .addMdocAttribute(
            //     DocumentAttributeType.Picture,
            //     "biometric_template_signature_sign",
            //     "Biometric Template Signature/Sign",
            //     "Signature/sign of the mDL holder",
            //     false,
            //     MDL_NAMESPACE
            // )
            // .addMdocAttribute(
            //     DocumentAttributeType.Picture,
            //     "biometric_template_iris",
            //     "Biometric Template Iris",
            //     "Iris of the mDL holder",
            //     false,
            //     MDL_NAMESPACE
            // )
            .build()
    }
}

