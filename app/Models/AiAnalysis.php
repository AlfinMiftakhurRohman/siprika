<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

#[Fillable(['finding_key', 'finding', 'threat', 'vulnerability', 'category', 'impact_description', 'recommendation', 'additional_control', 'model'])]
class AiAnalysis extends Model
{
    //
}
